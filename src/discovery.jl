const DISCOVERY_MCAST = ip"239.12.255.254"

function discovery_multicast()
    tags = [
        SpeedwireTag0(0xffffffff),
        SpeedwireTagDiscovery(),
        SpeedwireTagFinal(),
    ]
    return SpeedwirePacket(tags)
end

function sma_discovery(; addr = DISCOVERY_MCAST, port = SW_PORT, timeout = 5.0)
    discovery = condense(discovery_multicast())

    socket = UDPSocket()
    bind(socket, ip"0.0.0.0", 0)
    join_multicast_group(socket, addr)
    send(socket, addr, port, discovery)

    println("Waiting for responses...")
    responses = []
    while true
        t = @async recvfrom(socket)
        status = timedwait(() -> istaskdone(t), timeout)

        if status == :ok
            sender, data = fetch(t)
            push!(responses, (sender, data))
        else
            break
        end
    end

    close(socket)

    return responses
end
