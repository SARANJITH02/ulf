package com.ulpf.ingestion;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
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
public class SyslogUdpListener {

    private final IngestionService ingestionService;

    @Value("${ulpf.syslog.udp-enabled:true}")
    private boolean udpEnabled;

    @Value("${ulpf.syslog.udp-port:1514}")
    private int udpPort;

    private EventLoopGroup group;
    private Channel serverChannel;

    @PostConstruct
    public void start() {
        if (!udpEnabled) {
            log.info("Syslog UDP listener is disabled by configuration");
            return;
        }

        Thread listenerThread = new Thread(() -> {
            group = new NioEventLoopGroup(2);
            try {
                Bootstrap bootstrap = new Bootstrap();
                bootstrap.group(group)
                        .channel(NioDatagramChannel.class)
                        .option(ChannelOption.SO_BROADCAST, true)
                        .handler(new SimpleChannelInboundHandler<DatagramPacket>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
                                String msg = packet.content().toString(CharsetUtil.UTF_8);
                                try {
                                    ingestionService.ingestSingleLog(msg, "UDP_SYSLOG_" + udpPort);
                                } catch (Exception e) {
                                    log.error("Error processing UDP syslog packet: {}", e.getMessage());
                                }
                            }
                        });

                log.info("Starting Netty Syslog UDP listener on port {}...", udpPort);
                ChannelFuture future = bootstrap.bind(udpPort).sync();
                serverChannel = future.channel();
                log.info("Netty Syslog UDP listener active on port {}", udpPort);
                serverChannel.closeFuture().sync();
            } catch (Exception e) {
                log.warn("Syslog UDP listener failed or interrupted on port {}: {}", udpPort, e.getMessage());
            } finally {
                if (group != null) group.shutdownGracefully();
            }
        }, "syslog-udp-listener");

        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    @PreDestroy
    public void stop() {
        if (serverChannel != null) {
            serverChannel.close();
        }
        if (group != null) {
            group.shutdownGracefully();
        }
    }
}
