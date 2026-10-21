// Development-only, one-request HTTP server for a benign managed DLL fixture.
// The test substitutes the namespace for runspace isolation. Loopback by default.
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace EwrHttpFixture {
    public static class HttpFixture {
        private static TcpListener listener;
        private static Thread worker;
        public static int Port;
        public static string Error;
        public static bool Completed;

        public static void Start(string file) {
            Start(file, "127.0.0.1");
        }

        public static void Start(string file, string address) {
            byte[] body = File.ReadAllBytes(file);
            listener = new TcpListener(IPAddress.Parse(address), 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            worker = new Thread(delegate() {
                try {
                    using (TcpClient client = listener.AcceptTcpClient())
                    using (NetworkStream stream = client.GetStream())
                    using (StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true)) {
                        stream.ReadTimeout = 15000;
                        if (!reader.ReadLine().StartsWith("GET /Http.dll "))
                            throw new InvalidDataException("Unexpected HTTP fixture request");
                        int length = 0;
                        string line;
                        while (!String.IsNullOrEmpty(line = reader.ReadLine())) {
                            length += line.Length;
                            if (length > 8192) throw new InvalidDataException("Oversized HTTP header");
                        }
                        byte[] header = Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nContent-Length: " + body.Length +
                            "\r\nConnection: close\r\n\r\n");
                        stream.Write(header, 0, header.Length);
                        stream.Write(body, 0, body.Length);
                        Completed = true;
                    }
                } catch (Exception error) {
                    Error = error.ToString();
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }

        public static void Stop() {
            if (listener != null) listener.Stop();
            if (worker != null) worker.Join(20000);
        }
    }
}
