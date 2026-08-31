package com.ulpf.ingestion;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.util.CharsetUtil;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class SyslogTcpListener {

    private final IngestionService ingestionService;

    @Value("${ulpf.syslog.tcp-enabled:true}")
    private boolean tcpEnabled;

    @Value("${ulpf.syslog.tcp-port:1514}")
    private int tcpPort;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;

    @PostConstruct
    public void start() {
        if (!tcpEnabled) {
            log.info("Syslog TCP listener is disabled by configuration");
            return;
        }

        Thread listenerThread = new Thread(() -> {
            bossGroup = new NioEventLoopGroup(1);
            workerGroup = new NioEventLoopGroup(2);
            try {
                ServerBootstrap bootstrap = new ServerBootstrap();
                bootstrap.group(bossGroup, workerGroup)
                        .channel(NioServerSocketChannel.class)
                        .childHandler(new ChannelInitializer<SocketChannel>() {
                            @Override
                            protected void initChannel(SocketChannel ch) {
                                ChannelPipeline p = ch.pipeline();
                                p.addLast(new LineBasedFrameDecoder(65536, true, true));
                                p.addLast(new StringDecoder(CharsetUtil.UTF_8));
                                p.addLast(new SimpleChannelInboundHandler<String>() {
                                    @Override
                                    protected void channelRead0(ChannelHandlerContext ctx, String msg) {
                                        try {
                                            ingestionService.ingestSingleLog(msg, "TCP_SYSLOG_" + tcpPort);
                                        } catch (Exception e) {
                                            log.error("Error processing TCP syslog message: {}", e.getMessage());
                                        }
                                    }
                                });
                            }
                        })
                        .option(ChannelOption.SO_BACKLOG, 128)
                        .childOption(ChannelOption.SO_KEEPALIVE, true);

                log.info("Starting Netty Syslog TCP listener on port {}...", tcpPort);
                ChannelFuture future = bootstrap.bind(tcpPort).sync();
                serverChannel = future.channel();
                log.info("Netty Syslog TCP listener active on port {}", tcpPort);
                serverChannel.closeFuture().sync();
            } catch (Exception e) {
                log.warn("Syslog TCP listener failed or interrupted on port {}: {}", tcpPort, e.getMessage());
            } finally {
                if (bossGroup != null) bossGroup.shutdownGracefully();
                if (workerGroup != null) workerGroup.shutdownGracefully();
            }
        }, "syslog-tcp-listener");

        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    @PreDestroy
    public void stop() {
        if (serverChannel != null) {
            serverChannel.close();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
    }
}
