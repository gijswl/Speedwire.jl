abstract type UserGroup end
struct UGUser <: UserGroup end
struct UGInstaller <: UserGroup end

user_code(::UGUser) = 0x00000007
user_code(::UGInstaller) = 0x0000000A

pass_encode_char(::UGUser) = 0x88
pass_encode_char(::UGInstaller) = 0xBB

function encode_password(password::String, user::UserGroup)
    MAX_PWLENGTH = 12
    password_bytes = Vector{UInt8}(password)
    encode_char = pass_encode_char(user)
    pw = fill(encode_char, MAX_PWLENGTH)

    for (i, b) in enumerate(password_bytes)
        i > MAX_PWLENGTH && break
        pw[i] = b + encode_char
    end

    return pw
end

function login(socket::UDPSocket, host, user::UserGroup, password::String; source_id = 0x007d, source_serial = 0x0c000d0f)
    timestamp = UInt32(floor(datetime2unix(now())))

    data = IOBuffer()
    write(data, timestamp)
    write(data, 0x00000000)
    write(data, encode_password(password, user))

    destination = Endpoint(ANY_SUSYID, ANY_SERIAL, 0x0100)
    source = Endpoint(source_id, source_serial, 0x0100)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_LOGIN, user_code(user), 0x00000384, take!(data))
    response = query(socket, host, cmd)

    if (response.error_code != 0)
        error("Login error: $(error_string(response.error_code))")
    end

    println("Logged in.")

    return response
end

function logout(socket::UDPSocket, host; source_id = 0x007d, source_serial = 0x0c000d0f)
    destination = Endpoint(ANY_SUSYID, ANY_SERIAL, 0x0300)
    source = Endpoint(source_id, source_serial, 0x0300)
    cmd = InverterCommand(destination, source, get_packet_id(), CMD_LOGOUT, 0xffffffff, 0x00000000, [])
    send(socket, host, SW_PORT, condense(cmd))

    println("Logged out.")

    return # No response from the device
end
