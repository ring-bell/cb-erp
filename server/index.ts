import type { VercelRequest, VercelResponse } from '@vercel/node';
import authMe from './_handlers/auth';
import authPassword from './_handlers/auth/password';
import authLogin from './_handlers/auth/login';
import afterSales from './_handlers/after-sales';
import auditLogs from './_handlers/audit-logs';
import dbUsage from './_handlers/db-usage';
import inventory from './_handlers/inventory';
import permissions from './_handlers/permissions';
import products from './_handlers/products';
import productsBatchDelete from './_handlers/products/batch-delete';
import uploadImage from './_handlers/upload-image';
import purchaseOrders from './_handlers/purchase-orders';
import replenishment from './_handlers/replenishment';
import roles from './_handlers/roles';
import rolesId from './_handlers/roles/[id]';
import sales from './_handlers/sales';
import shipments from './_handlers/shipments';
import transfers from './_handlers/transfers';
import users from './_handlers/users';
import warehouses from './_handlers/warehouses';
import dashboard from './_handlers/dashboard';
import forwarders from './_handlers/forwarders';
import forwardersId from './_handlers/forwarders/[id]';
import afterSalesId from './_handlers/after-sales/[id]';
import inventoryId from './_handlers/inventory/[id]';
import inventoryAdjust from './_handlers/inventory/adjust';
import inventoryTransactions from './_handlers/inventory/transactions';
import productsId from './_handlers/products/[id]';
import purchaseOrdersId from './_handlers/purchase-orders/[id]';
import replenishmentId from './_handlers/replenishment/[id]';
import salesId from './_handlers/sales/[id]';
import shipmentsId from './_handlers/shipments/[id]';
import transfersId from './_handlers/transfers/[id]';
import usersId from './_handlers/users/[id]';
import warehousesId from './_handlers/warehouses/[id]';

type Handler = (req: VercelRequest, res: VercelResponse) => Promise<unknown> | unknown;

interface Route {
  pattern: RegExp;
  handler: Handler;
  params?: string[];
}

const routes: Route[] = [
  { pattern: /^\/auth\/login$/, handler: authLogin },
  { pattern: /^\/auth\/password$/, handler: authPassword },
  { pattern: /^\/auth\/me$/, handler: authMe },
  { pattern: /^\/dashboard\/stats$/, handler: dashboard },
  { pattern: /^\/forwarders\/([^/]+)$/, handler: forwardersId, params: ['id'] },
  { pattern: /^\/forwarders$/, handler: forwarders },
  { pattern: /^\/after-sales\/([^/]+)$/, handler: afterSalesId, params: ['id'] },
  { pattern: /^\/after-sales$/, handler: afterSales },
  { pattern: /^\/audit-logs$/, handler: auditLogs },
  { pattern: /^\/db-usage$/, handler: dbUsage },
  { pattern: /^\/inventory\/adjust$/, handler: inventoryAdjust },
  { pattern: /^\/inventory\/transactions$/, handler: inventoryTransactions },
  { pattern: /^\/inventory\/([^/]+)$/, handler: inventoryId, params: ['id'] },
  { pattern: /^\/inventory$/, handler: inventory },
  { pattern: /^\/permissions$/, handler: permissions },
  { pattern: /^\/products\/batch-delete$/, handler: productsBatchDelete },
  { pattern: /^\/products\/upload-image$/, handler: uploadImage },
  { pattern: /^\/products\/([^/]+)$/, handler: productsId, params: ['id'] },
  { pattern: /^\/products$/, handler: products },
  { pattern: /^\/purchase-orders\/([^/]+)$/, handler: purchaseOrdersId, params: ['id'] },
  { pattern: /^\/purchase-orders$/, handler: purchaseOrders },
  { pattern: /^\/replenishment\/([^/]+)$/, handler: replenishmentId, params: ['id'] },
  { pattern: /^\/replenishment$/, handler: replenishment },
  { pattern: /^\/roles$/, handler: roles },
  { pattern: /^\/roles\/([^/]+)$/, handler: rolesId, params: ['id'] },
  { pattern: /^\/sales\/([^/]+)$/, handler: salesId, params: ['id'] },
  { pattern: /^\/sales$/, handler: sales },
  { pattern: /^\/shipments\/([^/]+)$/, handler: shipmentsId, params: ['id'] },
  { pattern: /^\/shipments$/, handler: shipments },
  { pattern: /^\/transfers\/([^/]+)$/, handler: transfersId, params: ['id'] },
  { pattern: /^\/transfers$/, handler: transfers },
  { pattern: /^\/users\/([^/]+)$/, handler: usersId, params: ['id'] },
  { pattern: /^\/users$/, handler: users },
  { pattern: /^\/warehouses\/([^/]+)$/, handler: warehousesId, params: ['id'] },
  { pattern: /^\/warehouses$/, handler: warehouses },
];

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const url = new URL(req.url || '/', 'http://internal');
    const path = url.pathname.replace(/^\/api/, '') || '/';

    for (const route of routes) {
      const m = path.match(route.pattern);
      if (m) {
        if (route.params) {
          const q: Record<string, string | string[]> = { ...(req.query as Record<string, string | string[]>) };
          route.params.forEach((p, i) => {
            q[p] = m[i + 1];
          });
          (req as any).query = q;
        }
        return route.handler(req, res);
      }
    }

    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found' } });
  } catch (e) {
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Unexpected error' } });
  }
}
