const CMD_DISCOVERY = 0x00000200

const CMD_QUERY_AC = 0x51000200
const CMD_QUERY_STATUS = 0x51800200
const CMD_QUERY_TEMP = 0x52000200
const CMD_QUERY_DC = 0x53800200
const CMD_QUERY_ENERGY = 0x54000200
const CMD_QUERY_DEVICE = 0x58000200
const CMD_QUERY_YIELD_MINUTE = 0x70000200
const CMD_QUERY_EVENT = 0x70100200
const CMD_QUERY_YIELD_DAY = 0x70200200

const CMD_LOGIN = 0xfffd040c
const CMD_LOGOUT = 0xfffd01e0

struct InverterCommand
    destination::Endpoint
    destination_ctrl::UInt16
    source::Endpoint
    source_ctrl::UInt16
    packet_id::UInt16
    command::UInt32
    argument1::UInt32
    argument2::UInt32
    payload::Array{UInt8}
end

function condense(command::InverterCommand)
    data_tag = TagData2(
        0x6065,
        0xa0,
        command.destination,
        command.destination_ctrl,
        command.source,
        command.source_ctrl,
        0,
        0,
        command.packet_id,
        command.command,
        command.argument1,
        command.argument2,
        command.payload
    )

    tags = [
        Tag0(0x00000001),
        data_tag,
        TagFinal(),
    ]
    return condense(Packet(tags))
end

struct InverterResponse
    destination::Endpoint
    destination_ctrl::UInt16
    source::Endpoint
    source_ctrl::UInt16
    error_code::UInt16
    fragment_counter::UInt16
    packet_id::UInt16
    command::UInt32
    argument1::UInt32
    argument2::UInt32
    payload::Array{UInt8}
end

function InverterResponse(bytes::Array{UInt8})
    packet = Packet(bytes)
    data = get_tag(packet, TagData2)

    return InverterResponse(
        data.destination,
        data.destination_ctrl,
        data.source,
        data.source_ctrl,
        data.error_code,
        data.fragment_counter,
        data.packet_id,
        data.command,
        data.first_register,
        data.last_register,
        data.data
    )
end

function query(socket::UDPSocket, host, command::InverterCommand)
    send(socket, host, SW_PORT, condense(command))

    response = nothing
    while true
        rcv = timed_receive(socket, 5.0)
        if (isnothing(rcv))
            error("Request timed out.")
        end

        response = InverterResponse(rcv[2])
        if (response.packet_id & 0x7fff == command.packet_id)
            break
        else
            println("Received unexpected packet id $(rpacket.packet_id & 0x7fff)")
        end
    end

    return response
end
