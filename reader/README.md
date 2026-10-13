# client
Support for reading from the card.

Adds a "online with offline option"-approach where card is dumped and parsed in the background. 

The card dump is enough to call the server. If the server call goes wrong, it is possible to continue with offline based on the card dump. 

The factories are thread safe and meant to be shared by all card readers; the processors run on an `Executor`. See [Threads and reuse](../README.md#threads-and-reuse).
