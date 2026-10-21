using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
public sealed class EwrTcpEcho : IDisposable {
 readonly TcpListener listener;
 readonly List<TcpClient> clients = new List<TcpClient>();
 int active;
 public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
 public int Active { get { return Interlocked.CompareExchange(ref active,0,0); } }
 public EwrTcpEcho(bool ipv6) {
  listener = new TcpListener(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback,0);
  listener.Start();
  var thread = new Thread(Accept); thread.IsBackground=true; thread.Start();
 }
 void Accept() {
  try { while(true) {
   var client = listener.AcceptTcpClient(); lock(clients) clients.Add(client);
   Interlocked.Increment(ref active);
   var thread = new Thread(()=>Echo(client)); thread.IsBackground=true; thread.Start();
  }} catch(SocketException) {} catch(ObjectDisposedException) {}
 }
 void Echo(TcpClient client) {
  try { using(client) {
   var stream=client.GetStream(); var hello=System.Text.Encoding.ASCII.GetBytes("HELLO");
   stream.Write(hello,0,hello.Length); var buffer=new byte[65536]; int count;
   while((count=stream.Read(buffer,0,buffer.Length))>0) stream.Write(buffer,0,count);
   var bye=System.Text.Encoding.ASCII.GetBytes("BYE"); stream.Write(bye,0,bye.Length);
  }} catch(System.IO.IOException) {} catch(ObjectDisposedException) {} finally {
   lock(clients) clients.Remove(client); Interlocked.Decrement(ref active);
  }
 }
 public void Dispose() {listener.Stop(); lock(clients) foreach(var c in clients) c.Close();}
}
