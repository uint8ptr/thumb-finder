# Thumb finder

IDA Pro script that scans for Thumb-2 functions inside a database.

At the moment it was tested only on a Cortex-M3 bare-metal firmware I compiled myself, so don't expect much reliability.

It doesn't support any ARM instruction for the moment.

# How to use

The script is meant to be used by calling 3 functions:

```python
find_functions_lazy()
```

Checks for function prologues and tries to create a function whenever it finds one.

```python
find_functions_neighbors()
```

Looks for function epilogues next to already discovered functions, and creates functions if it finds any.

```python
find_functions()
```

Executes the two functions above and runs IDA autoanalysis.
