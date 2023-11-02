function updateinfo() {
    $.get('/api/info', function (data) {
        $('#code-user').text(data.user.Id)
        $('#code-money').text(data.user.Money)

        $('#item-div>ul').find('li').remove()

        let items = data.user.Items
        if (Object.keys(items).length > 0) {
            $('#item-div>p').text('You have the following items:')
            for (let k in items) {
                $('#item-div>ul').append(`<li>${k}: <code>${items[k]}</code></li>`)
            }
        } else {
            $('#item-div>p').text("You don't have bought anything yet")
        }
        $('#item-div').show()
    })
}

function getflag() {
    $.get('/api/flag', function(data) {
        $('#notice').html(data.message).show()

        updateinfo()
    })
}

function reset() {
    $.get('/api/reset', function (data) {
        $('#notice').html(data.message).show()

        updateinfo()
    })
}

function buy(name) {
    let num = $(`#${name}-num`).val()
    if (!num) {
        $('#notice').html(`Product num can't be empty`).show()
    } else {
        $.ajax({
            type: 'POST',
            url: '/api/buy',
            contentType: 'application/json',
            data: JSON.stringify({'name': name, 'num': num}),
            success: function (data) {
                $('#notice').html(data.message).show()

                updateinfo()
            }
        })
    }
}

function sell(name) {
    let num = $(`#${name}-num`).val()
    if (!num) {
        $('#notice').html(`Product num can't be empty`).show()
    } else {
        $.ajax({
            type: 'POST',
            url: '/api/sell',
            contentType: 'application/json',
            data: JSON.stringify({'name': name, 'num': num}),
            success: function (data) {
                $('#notice').html(data.message).show()

                updateinfo()
            }
        })
    }
}

window.addEventListener("load", updateinfo)