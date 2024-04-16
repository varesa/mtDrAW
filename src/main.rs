use etherparse::icmpv4::TimeExceededCode;
use etherparse::NetSlice::Ipv4;
use etherparse::{Icmpv4Type, PacketBuilder, SlicedPacket, TransportSlice};
use std::io::{Read, Write};
use TransportSlice::Icmpv4;

fn main() {
    let mut config = tun::Configuration::default();
    config
        .address((169, 254, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    config.platform(|config| {
        config.packet_information(true);
    });

    let mut dev = tun::create(&config).unwrap();
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        let slice = &buf[4..amount];
        //println!("{:?}", slice);

        let packet = SlicedPacket::from_ip(slice);
        //println!("{:#?}", &packet);

        if let Ok(SlicedPacket {
            net: Some(Ipv4(ip)),
            transport: Some(Icmpv4(icmp)),
            ..
        }) = &packet
        {
            if let Icmpv4Type::EchoRequest(echo_request) = &icmp.icmp_type() {
                let ttl = ip.header().ttl();

                let result = if ttl < 10 {
                    let mut new_source = ip.header().destination();
                    new_source[3] = ttl + 1;
                    let new_destination = ip.header().source();

                    let new_packet = PacketBuilder::ipv4(new_source, new_destination, 255).icmpv4(
                        Icmpv4Type::TimeExceeded(TimeExceededCode::TtlExceededInTransit),
                    );

                    let mut result = Vec::<u8>::with_capacity(new_packet.size(28) + 4);
                    result.write_all(&buf[0..4]).unwrap();
                    new_packet.write(&mut result, &buf[4..32]).unwrap();

                    result
                } else {
                    let new_source = ip.header().destination();
                    let new_destination = ip.header().source();

                    let new_packet = PacketBuilder::ipv4(new_source, new_destination, 255)
                        .icmpv4_echo_reply(echo_request.id, echo_request.seq);

                    let mut result = Vec::<u8>::with_capacity(new_packet.size(0) + 4);
                    result.write_all(&buf[0..4]).unwrap();
                    new_packet.write(&mut result, &[]).unwrap();

                    result
                };

                dev.write_all(&result).unwrap();
            }
        }
    }
}
