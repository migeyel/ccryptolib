# CCryptoLib
An integrated collection of cryptographic primitives written in Lua using the ComputerCraft system API.

## Initializing the Random Number Generator
All functions that take secret input may query the library's random generator,
`ccryptolib.random`. CC doesn't have high-quality entropy sources, so instead of
hoping for the best like other libraries do, CCryptoLib shifts that burden into
*you!*

### Initializing using a Trusted Web Source
If you trust the tmpim Krist node, you can fetch a socket token and use it for
initialization:
```lua
local random = require "ccryptolib.random"

-- Fetch a WebSocket token.
local postHandle = assert(http.post("https://krist.dev/ws/start", ""))
local data = textutils.unserializeJSON(postHandle.readAll())
postHandle.close()

-- Initialize the generator using the given URL.
random.init(data.url)

-- Be polite and actually open the socket too.
http.websocket(data.url).close()
```

### Initializing using VM Instruction Counting
As of v1.2.0, you can also initialize the generator using VM instruction timing noise.
See the `random.initWithTiming` method for security risks of taking this approach.
```lua
local random = require "ccryptolib.random"
random.initWithTiming()
```
