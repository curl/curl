public interface CurlWrite
{
  /**
   * handleString gets called by libcurl on each chunk of data
   * we receive from the remote server
   */
  public int handleString(byte s[]);
}

