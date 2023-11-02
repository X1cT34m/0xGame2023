from flask import Flask, request, render_template, session
import pickle
import uuid
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(2).hex()

class Note(object):
    def __init__(self, name, content):
        self._name = name
        self._content = content

    @property
    def name(self):
        return self._name
    
    @property
    def content(self):
        return self._content


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/<path:note_id>', methods=['GET'])
def view_note(note_id):
    notes = session.get('notes')
    if not notes:
        return render_template('note.html', msg='You have no notes')
    
    note_raw = notes.get(note_id)
    if not note_raw:
        return render_template('note.html', msg='This note does not exist')
    
    note = pickle.loads(note_raw)
    return render_template('note.html', note_id=note_id, note_name=note.name, note_content=note.content)


@app.route('/add_note', methods=['POST'])
def add_note():
    note_name = request.form.get('note_name')
    note_content = request.form.get('note_content')

    if note_name == '' or note_content == '':
        return render_template('index.html', status='add_failed', msg='note name or content is empty')
    
    note_id = str(uuid.uuid4())
    note = Note(note_name, note_content)

    if not session.get('notes'):
        session['notes'] = {}
    
    notes = session['notes']
    notes[note_id] = pickle.dumps(note)
    session['notes'] = notes
    return render_template('index.html', status='add_success', note_id=note_id)


@app.route('/delete_note', methods=['POST'])
def delete_note():
    note_id = request.form.get('note_id')
    if not note_id:
        return render_template('index.html')
    
    notes = session.get('notes')
    if not notes:
        return render_template('index.html', status='delete_failed', msg='You have no notes')
    
    if not notes.get(note_id):
        return render_template('index.html', status='delete_failed', msg='This note does not exist')
    
    del notes[note_id]
    session['notes'] = notes
    return render_template('index.html', status='delete_success')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)