using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpPXE
{
    public class TftpClient
    {
        private string serverIp;
        private int serverPort;
        private int timeout;

        public TftpClient(string serverIp, int timeout = 5000)
        {
            this.serverIp = serverIp;
            this.serverPort = 69; 
            this.timeout = timeout;
        }

        public byte[] GetFile(string remoteFileName)
        {
            using (var udpClient = new UdpClient())
            {
                try
                {
                    udpClient.Client.ReceiveTimeout = timeout;

                    IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);

                    SendReadRequest(remoteFileName, serverEndPoint, udpClient);

                    IPEndPoint remoteEP = null;
                    List<byte> fileData = new List<byte>();
                    int expectedBlockNumber = 1;

                    while (true)
                    {
                        byte[] receiveData = udpClient.Receive(ref remoteEP);

                        if (receiveData.Length < 4)
                        {
                            Console.WriteLine("[!] Received packet is too short.");
                            return null;
                        }

                        short opcode = (short)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveData, 0));
                        short blockNumber = (short)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveData, 2));

                        if (opcode != 3) // DATA packet
                        {
                            Console.WriteLine("[!] Invalid opcode from TFTP server: " + opcode);
                            return null;
                        }

                        if (blockNumber == expectedBlockNumber)
                        {
                            byte[] data = new byte[receiveData.Length - 4];
                            Array.Copy(receiveData, 4, data, 0, data.Length);
                            fileData.AddRange(data);

                            SendAcknowledgment(blockNumber, remoteEP, udpClient);

                            if (data.Length < 512)
                            {
                                break; 
                            }

                            expectedBlockNumber++;
                        }
                        else
                        {
                            Console.WriteLine("[!] Unexpected block number received.");
                        }
                    }

                    return fileData.ToArray();
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("[!] Socket exception: " + ex.Message);
                    return null;
                }
            }
        }

        private void SendReadRequest(string fileName, IPEndPoint serverEndPoint, UdpClient udpClient)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(ms);
            writer.Write(new byte[] { 0x00, 0x01 });
            writer.Write(Encoding.ASCII.GetBytes(fileName));
            writer.Write((byte)0);

            writer.Write(Encoding.ASCII.GetBytes("octet"));
            writer.Write((byte)0);

            byte[] rrqPacket = ms.ToArray();

            udpClient.Send(rrqPacket, rrqPacket.Length, serverEndPoint);
        }

        private void SendAcknowledgment(short blockNumber, IPEndPoint remoteEP, UdpClient udpClient)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(ms);

            writer.Write(new byte[] { 0x00, 0x04 });

            byte[] blockNumBytes = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder(blockNumber));
            writer.Write(blockNumBytes);

            byte[] ackPacket = ms.ToArray();

            udpClient.Send(ackPacket, ackPacket.Length, remoteEP);
        }
    }
}
