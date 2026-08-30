#pragma once
#include <string>
#include <functional>
#include <windows.h>

namespace PipeClient {
    bool Connect();                      // tries once; returns true on success
    void Disconnect();
    bool IsConnected();

    bool Send(const std::string& json);
    bool Heartbeat();                    // sends {"heartbeat":true}

    // Blocking read loop — calls cb for each complete message.
    // Returns when stopEvent is signalled or pipe breaks.
    void PumpMessages(std::function<void(const std::string&)> cb, HANDLE stopEvent);
}
