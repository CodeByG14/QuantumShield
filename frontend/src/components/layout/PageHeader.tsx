interface PageHeaderProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
  backAction?: React.ReactNode;
}

export function PageHeader({ title, description, action, backAction }: PageHeaderProps) {
  return (
    <div className="mb-8">
      {backAction && <div className="mb-3">{backAction}</div>}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-text-0">{title}</h1>
          {description && (
            <p className="mt-2 text-text-2 max-w-2xl">{description}</p>
          )}
        </div>
        {action && <div className="ml-4">{action}</div>}
      </div>
    </div>
  );
}
