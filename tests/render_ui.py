# -*- coding: utf-8 -*-
# Real offscreen Swing previews with synthetic data only.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.environ.get('RECON_TEST_TARGET')=='source':
    from recon.burp import extension as r
else:
    import ReconSwissKnife_v3 as r
from java.awt.image import BufferedImage
from java.awt import RenderingHints
from java.io import File
from javax.imageio import ImageIO
from javax.swing import SwingUtilities
class Engine(object):
    def get_active_count(self): return 0
class Ext(object): pass
class Msg(object): pass
ext=Ext(); ext.store=r.DataStore(); ext.scope=r.ScopeFilter(); ext.engine=Engine(); ext.enabled=False
for path in ('/api/invoices/123?userId=7&amount=10','/search?q=test','/account?tenant=example','/profile?displayName=sample'):
    url='https://app.example.test'+path
    ext.store.add_endpoint(url,'GET',set(['userId']),Msg())
    ext.store.add_parameters(url,r.extract_parameters(url),Msg())
ext.store.add_leak('Email','person@example.test','https://app.example.test/api/profile',Msg())
ext.store.add_leak('Iranian Mobile','09123456789','https://app.example.test/api/profile',Msg())
for record in r.scan_iranian(u'کد ملی: ۱۲۳۴۵۶۷۸۹۱; کد پستی: ۱۲۳۴۵۶۷۸۹۰'):
    ext.store.add_leak(record['type'],record['value'],'https://app.example.test/api/profile',Msg())
ext.store.add_parameters('https://app.example.test/api/profile',
    r.extract_parameters('https://app.example.test/api/profile',u'{"شناسه_کاربر":123,"مبلغ":1250}', 'application/json'),Msg())
def layout(c):
    c.doLayout()
    if hasattr(c,'getComponents'):
        for child in c.getComponents(): layout(child)
def render():
    r.UIManager.setLookAndFeel('javax.swing.plaf.nimbus.NimbusLookAndFeel')
    ui=r.ReconUI(ext); ui._do_refresh(); ui.panel.setSize(1600,900)
    for name,index in [('parameters',7),('pii',9)]:
        ui.tabs.setSelectedIndex(index); layout(ui.panel)
        table=ui._table_specs[index][0]
        if table.getRowCount(): table.setRowSelectionInterval(0,0)
        layout(ui.panel)
        image=BufferedImage(1600,900,BufferedImage.TYPE_INT_RGB); graphics=image.createGraphics()
        graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        try: ui.panel.printAll(graphics)
        finally: graphics.dispose()
        ImageIO.write(image,'png',File('/tmp/recon-'+r.VERSION+'-'+name+'.png'))
SwingUtilities.invokeAndWait(r._UiCall(render))
print('Rendered synthetic '+r.VERSION+' Parameters and PII previews.')
