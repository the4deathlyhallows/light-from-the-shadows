def sum_numbers(n):
    total = 0
    for i in range(1, n + 1):
        total += i
    return total

print(sum_numbers(5))    # 15 (1+2+3+4+5)
print(sum_numbers(10))   # 55
print(sum_numbers(100))  # 5050
print(sum_numbers(1))    # 1
