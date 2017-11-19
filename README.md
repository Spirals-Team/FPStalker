Repo containing the code of FPStalker's paper.

# Database
Change the connection to the database at the top of the main

# Get ids of browser instances with countermeasures
```ruby
python main.py getids
```

It generates a file called "consistent_extension_ids.csv" in data folder.

# Launch evaluation process of a linking algorithm

```ruby
python main.py auto myexpname nameoflinkingalgo 6
```

Where "myexpname" is the name of your experiment so that it can be used to prefix filenames,
"nameoflinkingalgo" is either eckersley or rulebased, and 6 must be replaced by the minimum number of fingerprints a browser instance need to be part of the experiment.

## For the Panopticlick/Eckersley linking algorithm
```ruby
python main.py auto myexpname eckersley 6
```

## For the rule-based linking algorithm
```ruby
python main.py auto myexpname rulebased 6
```

## For the hybrid linking algorithm
```ruby
python main.py automl myexpname 6
```

In current state, it loads the model contained in the data folder.
To train a new model, one just needs to change the load parameter of train_ml to False.
In order to optimize the lambda parameter, you just need to launch
```ruby
python main.py lambda
```

# Benchmark

For the hybrid algorithm:

```ruby
python automlbench myfilesprefix 4
```
Where 4 has to be replaced by the number of cores on your machine.

For the rule-based algorithm:
```ruby
python autorulesbench myfilesprefix 4
```
