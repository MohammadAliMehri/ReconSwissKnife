# Render the real Swing interface offscreen with synthetic data only.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.environ.get('RECON_TEST_TARGET') == 'source':
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
ext = Ext(); ext.store = r.DataStore(); ext.scope = r.ScopeFilter(); ext.engine = Engine(); ext.enabled = False
for i in range(16):
    ext.store.add_endpoint('https://app.example.test/api/projects/%d' % i, 'GET', set(['page', 'limit']), Msg())
    ext.store.add_js('https://app.example.test/assets/module-%d.js' % i, Msg())
ext.store.add_header_finding('https://app.example.test/account', 'Missing Content-Security-Policy', Msg())

def layout(component):
    component.doLayout()
    if hasattr(component, 'getComponents'):
        for child in component.getComponents(): layout(child)

def render():
    r.UIManager.setLookAndFeel('javax.swing.plaf.nimbus.NimbusLookAndFeel')
    ui = r.ReconUI(ext); ui._do_refresh()
    ui.panel.setSize(1440, 900); layout(ui.panel)
    ui.ep_table.setRowSelectionInterval(2, 2)
    for name, index in [('investigate',0), ('ai-review',1)]:
        ui.workspace_tabs.setSelectedIndex(index)
        if index == 1:
            ui.ai_context.setText('GET https://app.example.test/api/projects?page=[REDACTED]\nHTTP status: 200\ncontent-type: application/json\n\nResponse body:\n{"projects": [], "owner": "[REDACTED_EMAIL]"}')
        layout(ui.panel)
        image = BufferedImage(1440,900,BufferedImage.TYPE_INT_RGB)
        graphics = image.createGraphics()
        graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        try: ui.panel.printAll(graphics)
        finally: graphics.dispose()
        ImageIO.write(image, 'png', File('/tmp/recon-3.1.0-' + name + '.png'))
SwingUtilities.invokeAndWait(r._UiCall(render))
print('Rendered /tmp/recon-3.1.0-investigate.png and /tmp/recon-3.1.0-ai-review.png')
