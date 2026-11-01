const DATA_UNSIGNED32 = 0x00  # 0b0000 0000
const DATA_STATUS32   = 0x08  # 0b0000 1000
const DATA_STRING32   = 0x10  # 0b0001 0000
const DATA_FLOAT      = 0x20  # 0b0010 0000
const DATA_SIGNED32   = 0x40  # 0b0100 0000

const NAN_UNSIGNED32 = 0xffffffff
const NAN_STATUS32   = 0x00fffffd
const NAN_SIGNED32   = -2147483648 # 0x80000000

const EOD_STATUS32   = 0x00fffffe

abstract type InverterData end
struct InverterDataRaw <: InverterData
    register_id::UInt32
    connector::UInt8
    data_type::UInt8
    timestamp::UInt32
    data::Array{UInt8}
end

struct DataUnsigned32 <: InverterData 
    register_id::UInt32
    connector::UInt8
    timestamp::DateTime
    values::Array{UInt32}

    function DataUnsigned32(register_id, connector, timestamp, io, data_length)
        values = reinterpret(UInt32, read(io, data_length))
        values = get_significant_values(UInt32, values)

        return new(register_id, connector, timestamp, values)
    end
end

function get_significant_values(::Type{UInt32}, values)
    num_values = length(values)
    if(num_values == 2)
        values[2] == 0x00000000 && return [values[1]]
    elseif(num_values == 5)
        if(values[5] == 0x00000001)
            values[1] == values[2] && values[2] == values[3] && values[3] == values[4] && return [values[1]]
            values[3] == values[4] && return values[1:3]
            return values[1:4]
        end
    elseif(num_values == 8)
        values[1] == values[2] && values[3] == values[4] && values[5] == values[6] && values[7] == values[8]  && return values[1:2:end]
    end

    return num_values
end

struct DataStatus32 <: InverterData 
    register_id::UInt32
    connector::UInt8
    timestamp::DateTime
    values::Array{UInt32}
    selected::Int

    function DataStatus32(register_id, connector, timestamp, io, data_length)
        bytes = read(io, data_length)
        words = reinterpret(UInt32, bytes)
        values = UInt32[]
        selected = -1
        for (i, word) in enumerate(words)
            word == EOD_STATUS32 && break
            push!(values, word & 0x00ffffff)
            if(word >> 24 == 0x01)
                selected = i
            end
        end

        return new(register_id, connector, timestamp, values, selected)
    end
end

struct DataString32 <: InverterData 
    register_id::UInt32
    connector::UInt8
    timestamp::DateTime
    value::String

    function DataString32(register_id, connector, timestamp, io, data_length)
        bytes = read(io, data_length)
        zero_pos = findfirst(==(0), bytes)
        value = String(bytes[1:zero_pos-1])

        return new(register_id, connector, timestamp, value)
    end
end

struct DataFloat <: InverterData 

end

struct DataSigned32 <: InverterData 
    register_id::UInt32
    connector::UInt8
    timestamp::DateTime
    values::Array{Int32}

    function DataSigned32(register_id, connector, timestamp, io, data_length)
        values = reinterpret(Int32, read(io, data_length))
        values = get_significant_values(Int32, values)

        return new(register_id, connector, timestamp, values)
    end
end

function get_significant_values(::Type{Int32}, values)
    num_values = length(values)
    if(num_values == 2)
        values[2] == 0 && return [values[1]]
    elseif(num_values == 5)
        if(values[5] == 1)
            values[1] == values[2] && values[2] == values[3] && values[3] == values[4] && return [values[1]]
            values[3] == values[4] && return values[1:3]
            return values[1:4]
        end
    elseif(num_values == 8)
        values[1] == values[2] && values[3] == values[4] && values[5] == values[6] && values[7] == values[8]  && return values[1:2:end]
    end

    return num_values
end

function parse_data(io::IOBuffer, record_length::Int)
    word1 = read(io, UInt32)
    word2 = read(io, UInt32)

    register_id = word1 & 0x00ffff00
    connector = UInt8(word1 & 0x000000ff)
    data_type = UInt8(word1 >> 24)

    timestamp = unix2datetime(word2)

    if(data_type == DATA_UNSIGNED32)
        return DataUnsigned32(register_id, connector, timestamp, io, record_length - 8)
    elseif(data_type == DATA_STATUS32)
        return DataStatus32(register_id, connector, timestamp, io, record_length - 8)
    elseif(data_type == DATA_STRING32)
        return DataString32(register_id, connector, timestamp, io, record_length - 8)
    elseif(data_type == DATA_FLOAT)

    elseif(data_type == DATA_SIGNED32)
        return DataSigned32(register_id, connector, timestamp, io, record_length - 8)
    end
    
    return InverterDataRaw(register_id, connector, data_type, word2, read(io, record_length - 8))
end

function parse_data(response::InverterResponse)
    num_records = response.argument2 - response.argument1 + 1
    record_length = Int(length(response.payload) / num_records)

    data = InverterData[]
    io = IOBuffer(response.payload)

    for i in range(1, num_records)
        push!(data, parse_data(io, record_length))
    end

    return data
end

function throw_if_error(response, source)
    response.error_code != 0x0000 && error("[$source] Received error: $(error_string(response.error_code))")
end

function inverter_device_name(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DEVICE, 0x00821e00, 0x00821eff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_device_name")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_device_name] Unexpected data received: $data")
    typeof(data[1]) != DataString32 && error("[inverter_device_name] Unexpected data received: $(data[1])")

    return data[1].value
end

function inverter_device_class(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DEVICE, 0x00821f00, 0x00821fff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_device_class")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_device_class] Unexpected data received: $data")
    typeof(data[1]) != DataStatus32 && error("[inverter_device_class] Unexpected data received: $(data[1])")

    selected_status = data[1].values[data[1].selected]

    return selected_status
end

function inverter_device_type(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DEVICE, 0x00822000, 0x008220ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_device_type")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_device_type] Unexpected data received: $data")
    typeof(data[1]) != DataStatus32 && error("[inverter_device_type] Unexpected data received: $(data[1])")

    selected_status = data[1].values[data[1].selected]

    return selected_status
end

function bcd_to_string(b::UInt8)
    bytes = [
        0x30 + ((b >> 4) & 0x0f)
        0x30 + ((b >> 0) & 0x0f)
    ]
    return String(bytes)
end

function inverter_software_revision(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DEVICE, 0x00823400, 0x008234ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_software_revision")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_software_revision] Unexpected data received: $data")
    typeof(data[1]) != DataUnsigned32 && error("[inverter_software_revision] Unexpected data received: $(data[1])")

    word = data[1].values[3]
    byte1 = UInt8((word >> 24) & 0xff)
    byte2 = UInt8((word >> 16) & 0xff)
    byte3 = UInt8((word >> 08) & 0xff)
    byte4 = UInt8((word >> 00) & 0xff)

    letters = ["N", "E", "A", "B", "R", "S"]

    str = bcd_to_string(byte1) * "." * bcd_to_string(byte2) * "." * bcd_to_string(byte3) * "." * letters[byte4 + 1]
    return str
end

function inverter_dc_power(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DC, 0x00251e00, 0x00251eff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_dc_power")

    data = parse_data(response)
    power = [NaN for _ in 1:length(data)]
    for d in data
        typeof(d) != DataSigned32 && error("[inverter_dc_power] Unexpected data received: $d")

        conn = d.connector
        d.values[1] == NAN_SIGNED32 && continue
        power[conn] = d.values[1]
    end

    return power
end

function inverter_dc_voltage(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DC, 0x00451f00, 0x00451fff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_dc_voltage")

    data = parse_data(response)
    voltage = [NaN for _ in 1:length(data)]
    for d in data
        typeof(d) != DataSigned32 && error("[inverter_dc_voltage] Unexpected data received: $d")

        conn = d.connector
        d.values[1] == NAN_SIGNED32 && continue
        voltage[conn] = Int(d.values[1]) / 1e2
    end

    return voltage
end

function inverter_dc_current(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_DC, 0x00452100, 0x004521ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_dc_current")

    data = parse_data(response)
    current = [NaN for _ in 1:length(data)]
    for d in data
        typeof(d) != DataSigned32 && error("[inverter_dc_current] Unexpected data received: $d")

        conn = d.connector
        d.values[1] == NAN_SIGNED32 && continue
        current[conn] = Int(d.values[1]) / 1e3
    end

    return current
end

function inverter_ac_power(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_AC, 0x00464000, 0x004642ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_ac_power")

    data = parse_data(response)
    power = [NaN for _ in 1:length(data)]
    lines = Dict(0x00464000 => 1, 0x00464100 => 2, 0x00464200 => 3)
    for d in data
        typeof(d) != DataSigned32 && error("[inverter_ac_power] Unexpected data received: $d")

        line = lines[d.register_id]
        d.values[1] == NAN_SIGNED32 && continue
        power[line] = d.values[1]
    end

    return power
end

function inverter_ac_voltage(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_AC, 0x00464800, 0x00464aff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_ac_voltage")

    data = parse_data(response)
    voltage = [NaN for _ in 1:length(data)]
    lines = Dict(0x00464800 => 1, 0x00464900 => 2, 0x00464a00 => 3)
    for d in data
        typeof(d) != DataUnsigned32 && error("[inverter_ac_voltage] Unexpected data received: $d")

        line = lines[d.register_id]
        d.values[1] == NAN_UNSIGNED32 && continue
        voltage[line] = d.values[1] / 1e2
    end

    return voltage
end

function inverter_ac_current(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_AC, 0x00465300, 0x004655ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_ac_current")

    data = parse_data(response)
    current = [NaN for _ in 1:length(data)]
    lines = Dict(0x00465300 => 1, 0x00465400 => 2, 0x00465500 => 3)
    for d in data
        typeof(d) != DataSigned32 && error("[inverter_ac_current] Unexpected data received: $d")

        line = lines[d.register_id]
        d.values[1] == NAN_SIGNED32 && continue
        current[line] = d.values[1] / 1e3
    end

    return current
end

function inverter_ac_frequency(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_AC, 0x00465700, 0x004657ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_ac_frequency")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_ac_frequency] Unexpected data received: $data")
    typeof(data[1]) != DataUnsigned32 && error("[inverter_ac_frequency] Unexpected data received: $(data[1])")

    return data[1].values[1] / 1e2
end

function inverter_energy_total(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_ENERGY, 0x00260100, 0x002601ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_energy_total")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_energy_total] Unexpected data received: $data")
    typeof(data[1]) != DataUnsigned32 && error("[inverter_energy_total] Unexpected data received: $(data[1])")

    return data[1].values[1] / 1e3
end

function inverter_energy_day(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_ENERGY, 0x00262200, 0x002622ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_energy_day")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_energy_day] Unexpected data received: $data")
    typeof(data[1]) != DataUnsigned32 && error("[inverter_energy_day] Unexpected data received: $(data[1])")

    return data[1].values[1] / 1e3
end

function inverter_status_operation(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_STATUS, 0x00214800, 0x002148ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_status_operation")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_status_operation] Unexpected data received: $data")
    typeof(data[1]) != DataStatus32 && error("[inverter_status_operation] Unexpected data received: $(data[1])")

    return data[1].values[data[1].selected]
end

function inverter_status_relay(socket, target, destination, source)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_QUERY_STATUS, 0x00416400, 0x004164ff, [])
    response = query(socket, target, cmd)

    throw_if_error(response, "inverter_status_relay")

    data = parse_data(response)
    length(data) != 1 && error("[inverter_status_relay] Unexpected data received: $data")
    typeof(data[1]) != DataStatus32 && error("[inverter_status_relay] Unexpected data received: $(data[1])")

    return data[1].values[data[1].selected]
end