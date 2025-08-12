using System;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Simple .NET Application Started");
            Console.WriteLine($"Application started at: {DateTime.Now}");
            
            // Keep the application running
            while (true)
            {
                Console.WriteLine($"Application is running... {DateTime.Now}");
                await Task.Delay(5000); // Wait 5 seconds
            }
        }
    }
}