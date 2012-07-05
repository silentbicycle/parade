`parade`: run multiple commands in parallel and coordinate their output.

# Command line options #

    -h          print help
    -b SIZE     use a SIZE-byte buffer for task reads (def. 4096)
    -t COUNT    spawn at most COUNT tasks at a time (def. 10)
    
Each line of the command's input should be a shell command (to be
processed by system(3)), optionally preceded by a name and a colon.

If any of the tasks exit with a non-zero status, `parade` will kill its
child processes, halt, and return the same status code.

# Example usage #

    cat <<HERE | ./parade
    foo: command_that_prints 1 2 3 4 5
    bar: command_that_prints $(range 1 1000)
    baz: command_that_prints 10 20 30 40 50
    command_that_prints 100 200 300 400 500
    HERE
    
will spawn all the commands in parallel, yielding output like

    command_that_prints 100 200 300 400 500: 100
    command_that_prints 100 200 300 400 500: 200
    command_that_prints 100 200 300 400 500: 300
    command_that_prints 100 200 300 400 500: 400
    command_that_prints 100 200 300 400 500: 500
    baz: 10
    baz: 20
    baz: 30
    baz: 40
    baz: 50
    foo: 1
    foo: 2
    foo: 3
    foo: 4
    foo: 5
    bar: 0001
    bar: 0002
    bar: 0003
    bar: 0004
    bar: 0005
    ...
