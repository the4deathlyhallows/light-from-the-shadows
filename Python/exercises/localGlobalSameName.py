from time import process_time_ns


def spam():
    eggs = 'spam local'
    print(eggs) #Prints 'spam local'

def bacon():
    eggs = 'local bacon'
    print(eggs) # Prints 'local bacon'
    spam()
    print(eggs) # Prints 'bacon local'

eggs = 'global'
bacon()
print(eggs) #prints 'global