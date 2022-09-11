﻿using System.Net.WebSockets;
using Domain.WebSockets;
using Moq;

namespace Domain.UnitTests.WebSockets;

public class ConnectionTests
{
    [Fact]
    public void Should_Create_New_Connection()
    {
        var openedWebsocketMock = new Mock<WebSocket>();
        openedWebsocketMock.Setup(x => x.State).Returns(WebSocketState.Open);

        var connection = new Connection(openedWebsocketMock.Object, 1, ConnectionType.Client, ConnectionVersion.V1, 1662395291241);
        
        Assert.True(Guid.TryParse(connection.Id, out _));
        Assert.Equal(WebSocketState.Open, connection.WebSocket.State);
        Assert.Equal(1, connection.EnvId);
        Assert.Equal(ConnectionType.Client, connection.Type);
        Assert.Equal(ConnectionVersion.V1, connection.Version);
        Assert.Equal(1662395291241, connection.ConnectedAt);
    }
}