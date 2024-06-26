# Multi-channel setup in hyperledger fabric
## The channel 1 creation and deployment

>> cd test-network

#### Channel1.sh file creates the channel 1 and adds Fabric GW and Bob to the channel1.
>> ./channel1.sh

## Setting the Environment variables for Bob and Fabric Gateway
#### Open new terminals for Bob and run the following command
>> cd organization/Bob

#### Following file sets the environment variable for bob and creats its wallet.
>> source ./bob.sh

### Open another terminals for Fabric Gateway and run the following command
>> cd organization/FabricGW

#### Following file sets the environment variable for fabric Gateway and creats its wallet.
>> source ./fabricGW.sh

## The channel 2 creation and deployment
### In a new terminal
>> cd test-network

#### Channel1.sh file creates the channel 2 and adds Fabric GW and Denial to the channel2.
>> ./channel2.sh


## Setting the Environment variables for Denial
### Open new terminals for Denial and run the following command
>> cd organization/Denial

#### Following file sets the environment variable for denial and creats its wallet.
>> source ./denial.sh

### This terminal could be used by denial

