module Speedwire

const SW_PORT = 9522

using Dates
using Sockets

global packet_id = 1

function get_packet_id()
    global packet_id += 1
    return packet_id
end

include("error.jl")

include("packets.jl")

include("command.jl")

include("discovery.jl")

include("authentication.jl")

include("data.jl")

end # module Speedwire
