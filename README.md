# NetCom7

**The fastest communications possible.**

This is an updated version of NetCom7 with **IPv6 support**, **TLS/SSL security**, **new UDP components**, **threaded socket support**, and **dual protocol capabilities**. The library now offers a complete range of networking solutions while maintaining full backward compatibility with existing code.

## 🎯 **Latest Updates**
- **New UDP Support**: Complete UDP component family with three specialized types
- **Threaded Components**: High-performance TCP components with thread pool processing  
- **Dual Protocol**: Universal components supporting both raw data and structured commands
- **TLS/SSL Support**: Secure communications across all component types (Windows)
- **IPv6 Support**: Full IPv4/IPv6 compatibility (client and server must use same family)
- **New Demos**: Added comprehensive examples showcasing all new features and components

## 📋 **Component Overview**

### **TCP Components**

| Component | Classes | Description | Best For |
|-----------|---------|-------------|----------|
| **Raw TCP** | `TncTCPServer`<br/>`TncTCPClient` | Basic socket functionality | Simple protocols, learning, full control |
| **Threaded TCP** 🆕 | `TncTCPServerThd`<br/>`TncTCPClientThd` | Raw sockets + thread pool processing | High-performance custom protocols |
| **Dual TCP** 🆕 | `TncTCPServerDual`<br/>`TncTCPClientDual` | Raw data + command protocol support | Universal applications, maximum flexibility |
| **Command Sources** | `TncServerSource`<br/>`TncClientSource` | Command-based communication | RPC systems, legacy applications |
| **Database** | `TncDBServer`<br/>`TncDBDataset` | Database connectivity | Data synchronization, legacy support |

### **UDP Components**

| Component | Classes | Description | Best For |
|-----------|---------|-------------|----------|
| **Raw UDP** 🆕 | `TncUDPServer`<br/>`TncUDPClient` | Basic UDP functionality | Custom protocols, maximum performance |
| **LCP UDP** 🆕 | `TncUDPServerLCP`<br/>`TncUDPClientLCP` | Command protocol only | RPC systems, structured communication |
| **Dual UDP** 🆕 | `TncUDPServerDual`<br/>`TncUDPClientDual` | Raw data + command protocol support | Universal UDP applications |

**Legend:** 🆕 New in this version


## ⚡ **Key Features**
- **Auto-chunking**: Large data automatically split and reassembled
- **TLS/SSL**: Secure communications with certificate support
- **Thread pools**: High-performance concurrent processing
- **Protocol detection**: Automatic routing of raw vs command data
- **IPv4/IPv6**: Full IPv4 and IPv6 support (client/server must use same family, no dual-stack sockets)
- **Cross-platform**: Windows, macOS, Linux compatibility