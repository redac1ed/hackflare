import { useNavigate } from "react-router"
import { Button } from "~/components/ui/button"

export default function BadGateway() {
  const navigate = useNavigate()

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <div className="mb-8">
          <div className="mb-4 text-8xl font-bold text-orange-500">502</div>
          <h1 className="mb-2 text-3xl font-bold tracking-tight">
            Backend unreachable
          </h1>
          <p className="text-lg text-muted-foreground">
            The API server is not responding. The backend may be down or
            restarting. Please try again shortly.
          </p>
        </div>

        <div className="flex justify-center gap-3">
          <Button variant="default" onClick={() => navigate("/")}>
            Go home
          </Button>
          <Button variant="outline" onClick={() => navigate(0)}>
            Retry
          </Button>
        </div>
      </div>
    </div>
  )
}
