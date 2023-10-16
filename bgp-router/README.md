# APPROACH
To complete the project, we made a forwarding table class with a table and its own methods. This class had a dictionary that acted as the main table, which each key being a router that could be reached, and the value being a list of networks that can be reached if our router sends to the key router. In our router class, we made a dictionary for announcements and a dictionary for revocations, with the key being the router, and the values being the networks given in the update messages (for announcements) or the withdraw messages (for revocations).

# CHALLENGES
Challenges we faced took place during our aggregation process, which we had to edit multiple times. The first approach we made only handled aggregation after all updates had been given, so when we aggregated after each individual update (as specified in the project guidelines), it did not aggregate correctly. Our next approach was more correct and worked after each update. We calculated the binary representation of the networks and the netmask. Where the netmask was last 1, we call that index i, we check at i if both networks have different bits. After that, there was still a slight bug during disaggregation. This was because even after checking if the networks had different bits at i, we forgot to check if the bits in the network were all the same before and leading up to i. After doing that, our code coalesced and disaggregated correctly. 

# GOOD PROPERTIES/FEATURES
A good property in our code is each possible message and response is trackable from the same method, which is process_msg.

# TESTING
To test, we used the tests given to us, focusing on one set at a time and reading the output of the simulation to help. We also put our own print statements to know what was going on during the simulation. For instance, we had to print the table whenever we updated or withdrew networks to make sure we were making changed correctly. During the rebuilding of the table, we would print out the revocations and announcements to make sure we had the correct items to rebuild the list. And when finding the bets route, we printed out the network prefixes to make sure we were choosing the right one. 
