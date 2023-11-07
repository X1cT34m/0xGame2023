from sympy import symbols, Eq, solve

v7, v8, v9, v10, v11 = symbols('v7 v8 v9 v10 v11')

equations = [
    Eq(7 * v9 + 5 * (v8 + v11) + 2 * (v10 + 4 * v7), 0x12021DE669FC2),
    Eq(v9 + v10 + 2 * v10 + 2 * (v11 + v7) + v8, 0x159BFFC17D045 -
       2 * (v9 + v10 + 2 * v10 + 2 * (v11 + v7))),
    Eq(v10 + v9 + v11 + 2 * v9 + 2 * (v9 + v11 + 2 * v9) +
       2 * (v8 + 4 * v7), 0xACE320D12501),
    Eq(v8 + 2 * (v7 + v11 + v9 + 2 * v10), 0x733FFEB3A4FA),
    Eq(v8 + 7 * v11 + 8 * (v9 + v10) + 5 * v7, 0x1935EBA54EB28)
]

solutions = solve(equations)

sorted_solutions = {k: hex(v) for k, v in sorted(
    solutions.items(), key=lambda item: int(str(item[0])[1:]))}

formatted_sorted_hex_solution = f"0xGame{{{'-'.join([val[2:] for val in sorted_solutions.values()])}}}"

print(formatted_sorted_hex_solution)
