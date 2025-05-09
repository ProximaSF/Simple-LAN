from scapy.all import *
import textwrap

def main():
    msg = ''
    divider = '----'*5 + '\n'

    def check_interfaces():
        interface_info = []
        for i, int_face in enumerate(get_if_list(), 1):
            info = f'''
            {i}: {int_face}
            MAC Address: {get_if_hwaddr(int_face)}
            IP Address: {get_if_addr(int_face)}
            '''
            interface_info.append(textwrap.dedent(info))
        return '\n'.join(interface_info)
    print(check_interfaces())

    # Ethernet interface connection (Ethernet name in windows network setting)
    interface = 'Ethernet 8'


    my_frame = Ether() / IP()
    msg += (f'Packet/frame structure:\n'
            f'{my_frame}')

    packets = sniff(count=2, iface=interface) # Ping an address so can collect some packets from the network
    msg += (f"\n\nCapturing 2 packets From Network Sniffing:"
            f"\n{packets}")

    summary = [p.summary() for p in packets]
    msg += (f'\n\nDetailed Packet Summary (local -> some_server than some_server -> local):\n'
            f'{'\n'.join(summary)}')

    def packet_data(packet_order, layer, value=None):
        if layer not in packets[packet_order]:
            return f'Layer {layer} not found in {packet_order}'

        if value is None:
            packet_data = [i[packet_order][layer] for i in packets]
            return packet_data
        else:
            try:
                result = getattr(packets[packet_order][layer], value)
                return result
            except AttributeError:
                return f'Value {value} not found in {layer} layer of packet {packet_order}'


    msg += (f"\n\nAccessing Packet Data and Their Value:\n"
            f"First packet (0) Ether Layer:\n{packet_data(0, 'Ether')}\n"
            f"{divider}"
            f"Second packet (1) IP Layer:\n{packet_data(1, 'IP')}\n"
            f"{divider}"
            f"IP version for packet 1: {packet_data(1, 'IP', 'version')}")

    #--------------------------------------------------------------------------------

    # Filter packet for icmp (certain filter may not work if the packet does not have that protocol)
    packets2 = sniff(count=2, filter='icmp', iface=interface)
    msg += (f"\n\n=============================================================================================\n"
            f"\n\nCapturing 2 packets From Network Sniffing:"
            f"\n{packets2}")

    summary = [p.summary() for p in packets2]
    msg += (f'\n\nDetailed Packet Summary (local -> some_server than some_server -> local):\n'
            f'{'\n'.join(summary)}')

    def packet_data(packet_order, layer, value=None):
        if value:
            packet_data = [i[packet_order][layer] for i in packets2]
            a = ' '.join(packet_data)
            print(a)
            return packet_data
        else:
            packet_data = [i[packet_order][layer] for i in packets2]
            return packet_data

    msg += (f"\n\nAccessing Packet Data and Their Value:\n"
            f"First packet (0) Ether Layer:\n{packet_data(0, 'Ether')}\n"
            f"{divider}"
            f"Second packet (1) IP Layer:\n{packet_data(1, 'IP')}\n"
            f"{divider}"
            f"IP version for packet 0: {packets2[0][IP].version}")
    return msg




if __name__ == '__main__':
    file_path = 'LAN_info.txt'
    with open(file_path, 'w', encoding='UTF-8') as file:
        pass

    result = main()

    with open(file_path, 'a', encoding='utf-8') as read_file:
        read_file.write(result)