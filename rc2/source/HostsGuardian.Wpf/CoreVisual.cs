using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace DesignPrototype;

/// <summary>Abstract identity, never discovered topology. Native WPF vectors, no blur shader.</summary>
public sealed class CoreVisual:FrameworkElement
{
    public static bool ReducedMotion {get;set;}=!SystemParameters.ClientAreaAnimation;
    public static long TickCount,RenderCount;
    public static readonly List<double> RenderTimes=new();
    readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromMilliseconds(166)};
    double phase;
    ScrollViewer? viewport;
    Window? owner;
    public bool Minimal {get;set;}
    public double Reveal {get;set;}=1;
    public bool Active {get;set;}=true;
    public CoreVisual()
    {
        Focusable=false;IsHitTestVisible=false;SnapsToDevicePixels=true;
        AutomationProperties.SetName(this,"Security Core – absztrakt, dekoratív rendszermag, nem hálózati topológia");
        timer.Tick+=(_,_)=>{if(!InViewport()||ReducedMotion||!Active){timer.Stop();return;}phase+=.166;TickCount++;InvalidateVisual();};
        Loaded+=(_,_)=>{if(!Minimal){for(DependencyObject? p=VisualTreeHelper.GetParent(this);p!=null;p=VisualTreeHelper.GetParent(p))if(p is ScrollViewer scroll){viewport=scroll;viewport.ScrollChanged+=ViewportChanged;break;}owner=Window.GetWindow(this);if(owner!=null)owner.StateChanged+=OwnerChanged;}RefreshMotion();};
        Unloaded+=(_,_)=>{timer.Stop();if(viewport!=null)viewport.ScrollChanged-=ViewportChanged;if(owner!=null)owner.StateChanged-=OwnerChanged;viewport=null;owner=null;};IsVisibleChanged+=(_,_)=>RefreshMotion();SizeChanged+=(_,_)=>RefreshMotion();
    }
    void ViewportChanged(object sender,ScrollChangedEventArgs e)=>RefreshMotion();
    void OwnerChanged(object? sender,EventArgs e)=>RefreshMotion();
    bool InViewport()
    {
        if(!IsLoaded||!IsVisible||!SystemParameters.ClientAreaAnimation||owner?.WindowState==WindowState.Minimized)return false;
        if(viewport==null)return true;
        try{return TransformToAncestor(viewport).TransformBounds(new Rect(RenderSize)).IntersectsWith(new Rect(0,0,viewport.ActualWidth,viewport.ActualHeight));}catch(InvalidOperationException){return false;}
    }
    public void RefreshMotion(){if(InViewport()&&Active&&!Minimal&&!ReducedMotion)timer.Start();else timer.Stop();InvalidateVisual();}
    static readonly Dictionary<(Color,double,double),Pen> pens=new();
    static Pen Pen(string color,double width,double opacity=1){var value=Ui.Brush(color).Color;var key=(value,width,opacity);if(pens.TryGetValue(key,out var cached))return cached;var b=new SolidColorBrush(value){Opacity=opacity};b.Freeze();var pen=new Pen(b,width);pen.Freeze();if(pens.Count>512)pens.Clear();pens[key]=pen;return pen;}
    static StreamGeometry Path(IEnumerable<Point> points,bool closed=false)
    {
        var result=new StreamGeometry();using(var c=result.Open()){bool first=true;foreach(var p in points){if(first){c.BeginFigure(p,closed,closed);first=false;}else c.LineTo(p,true,false);}}result.Freeze();return result;
    }
    protected override void OnRender(DrawingContext dc)
    {
        var watch=Stopwatch.StartNew();double w=ActualWidth,h=ActualHeight;if(w<1||h<1)return;
        double scale=Minimal?Math.Min(w/120,h/130):Math.Min(w/440,h/350);dc.PushTransform(new ScaleTransform(scale,scale));dc.PushTransform(new TranslateTransform((w/scale-440)/2,(h/scale-350)/2));
        dc.PushOpacity(Math.Clamp(Reveal,0,1));
        if(!Minimal)
        {
            var halo=new RadialGradientBrush();halo.GradientStops.Add(new GradientStop(Color.FromArgb(95,0,154,255),0));halo.GradientStops.Add(new GradientStop(Color.FromArgb(16,0,121,240),.65));halo.GradientStops.Add(new GradientStop(Colors.Transparent,1));
            dc.DrawEllipse(halo,null,new Point(220,167),211,166);
            double breath=ReducedMotion?1:1+.018*Math.Sin(phase*.7);
            for(int ring=0;ring<5;ring++)
            {
                double rx=105+ring*22,ry=18+ring*5;
                dc.DrawEllipse(null,Pen(ring==1?"#47D9FF":"#186FA5",ring==1?2:1,.35+ring*.07),new Point(220,292),rx,ry);
            }
            dc.DrawEllipse(new RadialGradientBrush(Color.FromArgb(180,10,210,255),Colors.Transparent),null,new Point(220,290),106,25);
            dc.DrawEllipse(new RadialGradientBrush(Color.FromArgb(110,10,130,225),Color.FromArgb(16,2,20,49)),Pen("#81DFFF",1.6,.9),new Point(220,148),126*breath,126*breath);
            // Rotate an abstract wire sphere slowly. Back lines are subdued; no device semantics.
            Point Project(double lat,double lon,out double depth)
            {
                double x=Math.Cos(lat)*Math.Cos(lon),z=Math.Cos(lat)*Math.Sin(lon),y=Math.Sin(lat);double a=ReducedMotion?.4:phase/42+.4;
                double xx=x*Math.Cos(a)+z*Math.Sin(a);depth=-x*Math.Sin(a)+z*Math.Cos(a);return new Point(220+xx*124,148+y*124);
            }
            for(int lat=-60;lat<=60;lat+=20)
            {
                var pts=new List<Point>();for(int lon=0;lon<=360;lon+=10)pts.Add(Project(lat*Math.PI/180,lon*Math.PI/180,out _));dc.DrawGeometry(null,Pen("#3AB7ED",.7,.4),Path(pts));
            }
            for(int lon=0;lon<180;lon+=22)
            {
                var pts=new List<Point>();for(int lat=-90;lat<=270;lat+=10)pts.Add(Project(lat*Math.PI/180,lon*Math.PI/180,out _));dc.DrawGeometry(null,Pen("#56BFEF",.8,.48),Path(pts));
            }
            for(int k=0;k<18;k++)
            {
                var p=Project((k%5-2)*.34,k*2.399,out double depth);if(depth<-.2)continue;
                dc.DrawEllipse(new RadialGradientBrush(Color.FromArgb(190,55,217,255),Colors.Transparent),null,p,9,9);dc.DrawEllipse(Ui.Brush("#BAF4FF"),null,p,2.3,2.3);
            }
            var orbit=new List<Point>();for(int i=0;i<=64;i++){double a=i*Math.PI/32;orbit.Add(new Point(220+182*Math.Cos(a),203+43*Math.Sin(a)+35*Math.Cos(a)));}dc.DrawGeometry(null,Pen("#18CBFF",1,.45),Path(orbit));
            foreach(var (x,y) in new[]{(32.0,104.0),(398.0,80.0),(52.0,224.0),(392.0,228.0)})
            {
                dc.DrawLine(Pen("#267CAB",.8,.5),new Point(x,y),new Point(x<220?125:315,154));dc.DrawEllipse(Ui.Brush("#54DFFF"),null,new Point(x,y),2.2,2.2);
            }
        }
        double cx=220,cy=Minimal?175:150;
        for(int layer=2;layer>=0;layer--)
        {
            double y=cy-31+layer*26;var pts=new[]{new Point(cx,y-26),new Point(cx+48,y),new Point(cx,y+26),new Point(cx-48,y),new Point(cx,y-26)};
            dc.DrawGeometry(Ui.Brush(layer==0?"#12426A":"#102D4D"),Pen("#38D5FF",Minimal?5:4),Path(pts,true));
            dc.DrawGeometry(null,Pen("#A9F3FF",1,.7),Path(new[]{new Point(cx-32,y-1),new Point(cx,y-18),new Point(cx+32,y-1)}));
        }
        dc.Pop();dc.Pop();dc.Pop();watch.Stop();RenderCount++;
        if(RenderTimes.Count<4096)RenderTimes.Add(watch.Elapsed.TotalMilliseconds);
    }
}
