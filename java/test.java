import CurlGlue;
import CurlWrite;

class test implements CurlWrite {
    public int handleString(byte s[])
    {
        /* output everything */
        System.out.println("IIIIIIIIIII -------------- OOOOOOOOOOOOOOOOOOO");
        try {
          System.out.write(s);
        }
        catch (java.io.IOException moo) {
          // nothing
        }
        return 0;
    }

    public static void main(String[] args)
    {
        CurlGlue cg = new CurlGlue();
        test cw = new test();
        cg.setopt(CurlGlue.CURLOPT_URL, "http://www.contactor.se/");
        cg.setopt(CurlGlue.CURLOPT_WRITEFUNCTION, cw);
        cg.perform();
    }
}

