def is_palindrome(word):
    left, right = 0, len(word) - 1
    while left < right:
        if word[left] != word[right]:
            return False
        left += 1
        right -= 1
    return True

print(is_palindrome("level"))    # True
print(is_palindrome("meta"))     # False
print(is_palindrome(""))         # True
print(is_palindrome("a"))        # True
print(is_palindrome("racecar"))  # True
