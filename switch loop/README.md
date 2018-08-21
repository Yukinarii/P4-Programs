# Switch Loop Behavior Simulation

## Introduction

The objective of this program is to simulate a loop behavior in the bmv2 by resubmitting packets, to traverse an register array on the circumstance that p4 has no loop primitives.
## How to Run

Please put the directory under tutorials/SIGCOMM_2017/exercise, and run:

    ./run.sh

## Topology

The provided topology is 2 spine-leaf topology with 2 spine switches and 4 leaf switch. Each leaf switch is connected to 2 host server.

For the detailed, please take a look on p4app.json.

## Expected Result

(Empty)

## TODO

### Bug: 
    Iperf server doesn't reply acknowledgement packet.
    Global_timestamp keeps 0(Maybe some calculation statements are wrong)