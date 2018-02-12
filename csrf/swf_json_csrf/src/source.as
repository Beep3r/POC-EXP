package 
{
	import flash.display.Loader;
	import flash.display.LoaderInfo;
	import flash.display.Sprite;
	import flash.net.URLLoader;
	import flash.events.*;
	import flash.net.URLRequest;
	import flash.external.ExternalInterface;
	import flash.net.URLRequestHeader;
	import flash.net.URLRequestMethod;

	public class source extends Sprite 
	{

		public function source() 
		{
			var myJson: String = this.root.loaderInfo.parameters.jsonData;
			var endpoint: String = this.root.loaderInfo.parameters.endpoint;
			var php_url: String = (this.root.loaderInfo.parameters.php_url)?this.root.loaderInfo.parameters.php_url:"";
			var url: String = (php_url!="")?php_url:endpoint;
			var ct: String = (this.root.loaderInfo.parameters.ct)?this.root.loaderInfo.parameters.ct:"application/json";
			var request: URLRequest;
			if (php_url!="")
			{
			request=new URLRequest(url + "?endpoint=" + endpoint);
			}
			else 
			{
			request=new URLRequest(url);
			}
			request.requestHeaders.push(new URLRequestHeader("Content-Type", ct));
			request.data = (this.root.loaderInfo.parameters.reqmethod=="GET")?"":myJson;
			request.method = (this.root.loaderInfo.parameters.reqmethod)?this.root.loaderInfo.parameters.reqmethod:URLRequestMethod.POST;
			var urlLoader: URLLoader = new URLLoader();
			urlLoader.addEventListener(Event.COMPLETE, eventHandler);
			try 
			{
				urlLoader.load(request);
				return;
			}
			catch(e: Error) 
			{
				trace(e);
				return;
			}
		}
		
		public function eventHandler(event:Event):void
		{
			ExternalInterface.call("process",event.target.data);
		}
		
	}
}
