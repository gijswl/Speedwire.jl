const ERROR_CODES = Dict(
    0x0015 => "Requested LRI not available",
    0x0100 => "Invalid password",
    0xffff => "Receive buffer empty"
)

function error_string(error::UInt16)
    if (error in keys(ERROR_CODES))
        return ERROR_CODES[error]
    else
        return "0x" * string(error, base = 16, pad = 4)
    end
end
