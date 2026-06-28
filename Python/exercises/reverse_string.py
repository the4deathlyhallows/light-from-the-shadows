def reverse_string(s):
    if not isinstance(s, str):
        raise TypeError("reverse_string expects a string")

    """
    Return the reverse of string s.
    Example: reverse_string("meta") -> "atem"
    """
    return s[::-1]
print(reverse_string("meta"))      # "atem"
print(reverse_string("racecar"))   # "racecar"   (palindrome)
print(reverse_string(""))          # ""          (empty string)
print(reverse_string("a"))         # "a"         (single char)
