def read_lines(fname,lnum):
    try:
        with open(fname,"r"):
            lines = file.reallines()
    except:
        ("Error reading file")
        return

    total_lines = len(lines)

    if lnum > total_lines or lnum < 1:
        print(f"{total_lines} file lines.")
        print(f"Can't read line {lnum}!")
    else:
        line = lines[lnum - 1].rstrip('\n')
        print(line)


# Example usage:
    read_line("file.txt", 2)
    read_line("file.txt", 5)
