const SMA_SIGNATURE = UInt8[0x53, 0x4d, 0x41, 0x00]

const ID_TAG_FINAL = 0x0000
const ID_TAG_DATA2 = 0x0010
const ID_TAG_DISCOVERY = 0x0020
const ID_TAG_IP = 0x0030
const ID_TAG0 = 0x02a0

const ANY_SUSYID = 0xffff
const ANY_SERIAL = 0xffffffff

struct Endpoint
    SUSyID::UInt16
    serial::UInt32
    control::UInt16
end

function condense(endpoint::Endpoint)
    io = IOBuffer()

    write(io, endpoint.SUSyID)
    write(io, endpoint.serial)
    write(io, endpoint.control)

    return take!(io)
end

function parse_endpoint(io::IOBuffer)
    return Endpoint(
        read(io, UInt16),
        read(io, UInt32),
        read(io, UInt16)
    )
end

abstract type Tag end
function tag_data(::Tag) end
function tag_id(::Tag) end
function tag_length(::Tag) end

function condense(tag::Tag)
    io = IOBuffer()
    write(io, hton(tag_length(tag)))
    write(io, hton(tag_id(tag)))
    write(io, tag_data(tag))

    seekstart(io)
    return read(io)
end


struct Tag0 <: Tag
    group::UInt32
end
tag_length(::Tag0) = 0x0004
tag_id(::Tag0) = ID_TAG0
tag_data(tag::Tag0) = ntoh(tag.group)


struct TagDiscovery <: Tag end
tag_length(::TagDiscovery) = 0x0000
tag_id(::TagDiscovery) = ID_TAG_DISCOVERY
tag_data(::TagDiscovery) = UInt8[]


struct TagIP <: Tag
    ip::IPv4
end
tag_length(::TagIP) = 0x0004
tag_id(::TagIP) = ID_TAG_IP
function tag_data(tag::TagIP)
    io = IOBuffer()
    write(io, hton(tag.ip.host))

    seekstart(io)
    return read(io)
end


struct TagFinal <: Tag end
tag_length(::TagFinal) = 0x0000
tag_id(::TagFinal) = ID_TAG_FINAL
tag_data(::TagFinal) = UInt8[]


struct RawTag <: Tag
    tag_id::UInt16
    data::Array{UInt8}
end
tag_length(::RawTag) = UInt16(length(tag.data))
tag_id(::RawTag) = tag.tag_id
tag_data(::RawTag) = tag.data


struct TagData2 <: Tag
    protocol::UInt16
    control::UInt8
    destination::Endpoint
    source::Endpoint
    error_code::UInt16
    fragment_counter::UInt16
    packet_id::UInt16

    command::UInt32
    first_register::UInt32
    last_register::UInt32

    data::Array{UInt8}
end
tag_length(tag::TagData2) = UInt16(length(tag.data) + 38)
tag_id(::TagData2) = ID_TAG_DATA2
function tag_data(tag::TagData2)
    length_words = UInt8((length(tag.data) + 36) / 4)

    io = IOBuffer()
    write(io, hton(tag.protocol))
    write(io, length_words)
    write(io, tag.control)
    write(io, condense(tag.destination))
    write(io, condense(tag.source))
    write(io, tag.error_code)
    write(io, tag.fragment_counter)
    write(io, tag.packet_id | 0x8000)
    write(io, tag.command)
    write(io, tag.first_register)
    write(io, tag.last_register)
    write(io, tag.data)

    seekstart(io)
    return read(io)
end

function parse_tag(::Type{TagData2}, io::IOBuffer)
    protocol = ntoh(read(io, UInt16))
    length_words = read(io, UInt8)
    control = read(io, UInt8)
    destination = parse_endpoint(io)
    source = parse_endpoint(io)
    error_code = read(io, UInt16)
    fragment_counter = read(io, UInt16)
    packet_id = read(io, UInt16)
    command = read(io, UInt32)
    first_register = read(io, UInt32)
    last_register = read(io, UInt32)

    data_length = length_words * 4 - 36
    data = read(io, data_length)

    return TagData2(protocol, control, destination, source, error_code, fragment_counter, packet_id, command, first_register, last_register, data)
end


function parse_tag(io::IOBuffer)
    data_length = ntoh(read(io, UInt16))
    tag_id = ntoh(read(io, UInt16))

    if (tag_id == ID_TAG_FINAL)
        return TagFinal()
    elseif (tag_id == ID_TAG_DATA2)
        return parse_tag(TagData2, io)
    elseif (tag_id == ID_TAG_DISCOVERY)
        return TagDiscovery()
    elseif (tag_id == ID_TAG_IP)
        ip = IPv4(ntoh(read(io, UInt32)))
        return TagIP(ip)
    elseif (tag_id == ID_TAG0)
        group = ntoh(read(io, UInt32))
        return Tag0(group)
    else
        data = read(io, data_length)
        return RawTag(tag_id, data)
    end
end

struct Packet
    tags::Array{Tag}
end

Packet(bytes::Array{UInt8}) = Packet(IOBuffer(bytes))

function Packet(io::IOBuffer)
    header = read(io, 4)
    header == SMA_SIGNATURE || error("Header $header does not match SMA signature.")

    tags = Tag[]

    while true
        tag = parse_tag(io)
        push!(tags, tag)

        typeof(tag) <: TagFinal && break
    end

    return Packet(tags)
end

function condense(packet::Packet)
    io = IOBuffer()
    write(io, SMA_SIGNATURE)
    for tag in packet.tags
        write(io, condense(tag))
    end

    seekstart(io)
    return read(io)
end

function get_tag(packet::Packet, type::Type{<:Tag})
    for tag in packet.tags
        typeof(tag) == type && return tag
    end
    return nothing
end


function timed_receive(socket, timeout)
    #println("Waiting for response on socket for $timeout seconds...")
    t = @async recvfrom(socket)
    status = timedwait(() -> istaskdone(t), timeout)

    if status == :ok
        return fetch(t)
    else
        return nothing
    end
end
