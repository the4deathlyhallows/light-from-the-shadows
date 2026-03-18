from new import write_file


def say_hello(name):
    print("Hello " + name)
    print("Hello " + name + "!")
    print("Hello " + name + "!")
    print("Hello " + name + "!")
say_hello("Alicante")
say_hello("Bob")
say_hello("Carol")
say_hello("Jeff")
say_hello("Jeff")
say_hello("Jeff")


if __name__ == "__main__":
    with open('/Users/robert/Documents/write_file.txt', "w") as write_file:
        write_file.write(f' "Hello World" + {say_hello("Jeff")}')