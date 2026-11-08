import './style.css';
export const dynamic='force-dynamic';
export const metadata={title:'ATLAS · Research workspace',description:'Authorized research. Reproducible evidence.'};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
