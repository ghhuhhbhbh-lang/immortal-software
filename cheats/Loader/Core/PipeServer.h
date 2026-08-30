#pragma once
#include <windows.h>
#include <string>
#include <functional>

namespace PipeServer {

// Called when the DLL sends a JSON frame.
using MessageCb = std::function<void(const std::string& json)>;
// Called when the client connects / disconnects.
using ConnectCb  = std::function<void()>;
using DisconnectCb = std::function<void()>;

struct Callbacks {
    MessageCb    onMessage;
    ConnectCb    onConnect;
    DisconnectCb onDisconnect;
};

// Start the named-pipe server in a background thread.
// Returns true on success. Call Stop() before destruction.
bool  Start(Callbacks cbs);
void  Stop();
bool  IsClientConnected();

// Send a JSON command down to the connected DLL client.
// Thread-safe; returns false if no client or pipe write fails.
bool  Send(const std::string& json);

// Reset missed-beat counter and last-beat timestamp.
void  ResetHeartbeat();

// Returns false if MAX_MISSED_BEATS exceeded.
bool  HeartbeatOk();

} // namespace PipeServer
