module Speedwire

# https://github.com/Rincewind76/SMAInverter
# https://github.com/SBFspot/SBFspot
# https://github.com/RalfOGit/libspeedwire

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

mutable struct Device
    socket::UDPSocket
    host::IPAddr
    destination::Endpoint
    source::Endpoint

    function Device(host_ip, target_ip, source)
        socket = UDPSocket()
        bind(socket, host_ip, 0)

        return new(socket, target_ip, ANY_ENDPOINT, source)
    end
end

function close(dev::Device)
    return Sockets.close(dev.socket)
end

include("command.jl")

include("discovery.jl")

include("authentication.jl")

include("data.jl")

end # module Speedwire
