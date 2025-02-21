## Send Flow
In all cases, the flow of sending a message is client-initiated in 100%, so there's not so much room for customizing per-backend, and the data flow is quite understandable.

Generally:
```mermaid
graph TD
    CH[ConnectionMessageHandler::sendo: high level logic - seq/flags/...] --> W[BaseWorker::send: tranform] --> B[BackendImpl::do_send]
```

For async backend:
```mermaid
graph TD
    subgraph W[Worker Thread]
        ABlfn[AsyncBackend::loop_fn]-->ABs[AsyncBackend::handle_next_msg select!Send,Receive,Quit]--2 Send data-->NBs[NetBiosClient::send]
        NBs --3 Done--> ABs --4 Done--> ABlfn
    end
    subgraph R[Requesting Thread]
        ABds[AsyncBackend::do_send] -.1 Send Channel.-> ABs
    end
```

For multi-threaded backend:
```mermaid
graph TD
    subgraph W[Send Worker Thread]
        MBs[MultiThreadedBackend::loop_send]--2 Send data-->NBs[NetBiosClient::send]
        NBs --3 Done--> MBs
    end
    subgraph R[Requesting Thread]
        MBds[MultiThreadedBackend::do_send] -.1 Send Channel.-> MBs
    end
    subgraph Receive Worker Thread
    end
```

For single-threaded backend:
```mermaid
graph TD
    subgraph Main Thread
        SBs[SingleThreadedBackend::do_send]--1 Send data-->NBs[NetBiosClient::send]
    end
```