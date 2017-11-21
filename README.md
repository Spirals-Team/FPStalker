Repo containing the code of FPStalker's paper.

# Create virtual environment and install dependencies
Run the command below to create a virtual environment.
```ruby
virtualenv --python=/usr/bin/python3 myvenv
```

Then activate the virtual environment.
```ruby
. myvenv/bin/activate
```

Finally, install the dependencies.
```ruby
pip install -r requirements.txt
```

# Database
Create a database that will contain the table that stores the fingerprints.
Then, you have two solutions:
- Run the command below to generate a sql file tableFingerprints.sql with few fingerprints. It contains 15k fingerprints in this table that were randomly sampled from the first half of the raw dataset, i.e. with no filter.
The reason we split the table in two files is to overcome the Github storage limit.
```ruby
tar zxvf extension1.txt.tar.gz; tar zxvf extension2.txt.tar.gz; cat extension1.txt extension2.txt > tableFingerprints.sql
```
- Import extensionDataScheme.sql that contains only the scheme of the table to stores the fingerprints.

Change the connection to the database at the top of the main with your credentials.

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
In current state, it loads the random forest model contained in the `data/my_ml_model`.
It was generated on the conditions specified in the article, i.e. 
To train a new model, one just needs to change the load parameter of the `train_ml` function (in main) to False.
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
