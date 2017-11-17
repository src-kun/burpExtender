package burp;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener{
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private String ExtenderName = "Unicode decoder";

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		//64:REPEATER 32:INTRUDER 16:SCANNER 
		if(toolFlag == 64 || toolFlag == 32 || toolFlag == 16) {
			if(!messageIsRequest)  {
				byte[] response = messageInfo.getResponse();
				IResponseInfo analyzedResponse = helpers.analyzeResponse(response);
				List<String> headers = analyzedResponse.getHeaders();  //响应头
				String resp = new String(messageInfo.getResponse());  //响应包
				//截取出body字符串
				int bodyOffset = analyzedResponse.getBodyOffset();
				String body = resp.substring(bodyOffset);
				body = unicodeToString(body);
				//body还原成字节码
				byte[] bodybyte = body.getBytes();
				messageInfo.setResponse(helpers.buildHttpMessage(headers, bodybyte));
			}
		}	
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println(ExtenderName);
		helpers = callbacks.getHelpers();
		//设置拓展名
		callbacks.setExtensionName(ExtenderName);
		//注册HttpListener,处理请求和响应
		callbacks.registerHttpListener(this);
	}
	
	//unicode转中文
	public static String unicodeToString(String str) {
	    Pattern pattern = Pattern.compile("(\\\\u(\\p{XDigit}{4}))");    
	    Matcher matcher = pattern.matcher(str);
	    char ch;
	    while (matcher.find()) {
	        ch = (char) Integer.parseInt(matcher.group(2), 16);
	        str = str.replace(matcher.group(1), ch + "");    
	    }
	    return str;
	}
}
