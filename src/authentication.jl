abstract type UserGroup end
struct UGUser <: UserGroup end
struct UGInstaller <: UserGroup end

user_code(::UGUser) = 0x00000007
user_code(::UGInstaller) = 0x0000000a

pass_encode_char(::UGUser) = 0x88
pass_encode_char(::UGInstaller) = 0xbb

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

function login(dev::Device, user::UserGroup, password::String)
    timestamp = UInt32(floor(datetime2unix(now())))

    data = IOBuffer()
    write(data, timestamp)
    write(data, 0x00000000)
    write(data, encode_password(password, user))
    seekstart(data)
    payload = read(data)

    cmd = InverterCommand(
        dev.destination, 0x0100,
        dev.source, 0x0100,
        get_packet_id(),
        CMD_LOGIN,
        user_code(user),
        0x00000384,
        payload
    )
    response = query(dev.socket, dev.host, cmd)

    if (response.error_code != 0)
        error("Login error: $(error_string(response.error_code))")
    end

    println("Logged in.")

    dev.destination = response.source
    return response
end

function logout(dev::Device)
    cmd = InverterCommand(
        dev.destination, 0x0300,
        dev.source, 0x0300,
        get_packet_id(),
        CMD_LOGOUT,
        0xffffffff,
        0x00000000,
        []
    )
    send(dev.socket, dev.host, SW_PORT, condense(cmd))

    println("Logged out.")

    return # No response from the device
end
